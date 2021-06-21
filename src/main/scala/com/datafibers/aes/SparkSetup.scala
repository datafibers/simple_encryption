package com.datafibers.aes

import com.datafibers.aes.AesUtil.{cacheKeyFromFolders, encryptWithVer, getIvFromPassByte, getKeyFromPassByte, getKeyVersionByRule}
import org.apache.spark.SparkConf
import org.apache.spark.sql.{DataFrame, SparkSession}
import org.apache.spark.sql.functions.{col, lit, udf}
import org.slf4j.LoggerFactory

import java.util.Base64

trait SparkSetup {
  val appLogger = LoggerFactory.getLogger(this.getClass.getName)

  def setEncryptionProperties(sparkConf: SparkConf, pwdFilePath: String) = {
    val keyCache = new java.util.HashMap[String, Array[Byte]]()
    cacheKeyFromFolders(pwdFilePath, keyCache)
    val keyVer = getKeyVersionByRule(PasswordUtilConstant.DEFAULT_KEY_ROTATION_RULE, keyCache)
    val key = keyCache.get(keyVer)
    val keyEncoded = Base64.getEncoder.encodeToString(key)
    sparkConf.set("encryption.key.version", keyVer)
    sparkConf.set("encryption.pass.string", keyEncoded)
  }

  /**
   * Initialize Spark session alone with other encryption properties
   * @param applicationName
   * @param pwdFilePath
   * @return sparkSession
   */
  def sparkEnvInitialization(applicationName: String, pwdFilePath: String = null): SparkSession = {
    appLogger.info("Initializing the application successfully.")
    val sparkConf = new SparkConf().setAppName(applicationName)
    sparkConf.setMaster("local")
    try {
      setEncryptionProperties(sparkConf, pwdFilePath)
      val sparkSession = SparkSession.builder.config(sparkConf).enableHiveSupport.getOrCreate
      sparkSession
    } catch {
      case e: Exception =>
        throw new RuntimeException("Error in initializing spark session " + e.getCause)
    }
  }

  val encryptDataRow = udf {(plainText: String, keyVer: String, pass: Array[Byte]) =>
    encryptWithVer(plainText, getKeyFromPassByte(pass), getIvFromPassByte(pass), keyVer)
  }

  def dsEncrypt(inputDF: DataFrame, encryptCol: String)(implicit spark: SparkSession): DataFrame = {
    val keyVer = spark.sparkContext.getConf.get("encryption.key.version")
    val pass = spark.sparkContext.getConf.get("encryption.pass.string")
    val passDecoded = Base64.getDecoder.decode(pass)
    inputDF.columns.foldLeft(inputDF)((r, c) => {
      if (encryptCol == c) {
        r.withColumn(c, encryptDataRow(col(c), lit(keyVer), lit(passDecoded)))
      } else r
    })
  }

}
