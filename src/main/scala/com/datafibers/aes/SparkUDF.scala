package com.datafibers.aes

import com.datafibers.aes.AesUtil.{decryptWithVer, encryptWithVer, getIvFromPassByte, getKeyFromPassByte, getKeyVersionByRule}
import org.apache.spark.sql.{DataFrame, SparkSession}
import org.apache.spark.sql.functions.{broadcast, col, lit, udf}

import java.util
import java.util.{Base64, HashMap}
import scala.collection.JavaConverters.mapAsScalaMapConverter

trait SparkUDF {

  val encryptDataRow = udf {(plainText: String, keyVer: String, pass: Array[Byte]) =>
    encryptWithVer(plainText, getKeyFromPassByte(pass), getIvFromPassByte(pass), keyVer)
  }

  def dsEncrypt(inputDF: DataFrame, encryptCol: String, keyCache: HashMap[String, String])(implicit spark: SparkSession): DataFrame = {
    val keyVer = getKeyVersionByRule(PasswordUtilConstant.DEFAULT_KEY_ROTATION_RULE, keyCache)
    val passDecoded = Base64.getDecoder.decode(keyCache.get(keyVer))
    inputDF.columns.foldLeft(inputDF)((r, c) => {
      if (encryptCol.split(",").contains(c)) {
        r.withColumn(c, encryptDataRow(col(c), lit(keyVer), lit(passDecoded)))
      } else r
    })
  }

  val decryptDataRow = udf {(cipherText: String, pass: String) =>
    decryptWithVer(cipherText, pass)
  }

  val fetchDecryptKeyVersion = udf { (cipherText: String) =>
    val cipherTextDecoded = Base64.getDecoder.decode(cipherText)
    val keyVer = new String(util.Arrays.copyOf(cipherTextDecoded, PasswordUtilConstant.DEFAULT_KEY_VERSION_LENGTH))
    keyVer
  }

  def dsDecrypt(inputDF: DataFrame, decryptCol: String, keyCache: HashMap[String, String])(implicit spark: SparkSession): DataFrame = {
    import spark.implicits._
    val keyCacheDf = keyCache.asScala.toMap.toSeq.toDF("key_version", "pass")
    val firstCol = decryptCol.split(",")(0) // get first column to fetch all key version
    val inputDFWithKeyVer = inputDF.withColumn("key_version", fetchDecryptKeyVersion(col(firstCol)))
    val dfWithKey = inputDFWithKeyVer.join(broadcast(keyCacheDf), inputDFWithKeyVer("key_version") <=> keyCacheDf("key_version"))

    dfWithKey.columns.foldLeft(dfWithKey)((r, c) => {
      if (decryptCol.split(",").contains(c)) {
        r.withColumn(c, decryptDataRow(col(c), col("pass")))
      } else r
    }).drop("key_version", "pass")
  }

}