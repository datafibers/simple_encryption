package com.datafibers.aes

import com.datafibers.aes.AesUtil.{cacheKeyFromFolders, genKeyFile}
import org.apache.spark.sql.SparkSession
import org.junit.Assert.assertEquals
import org.junit.runner.RunWith
import org.scalatest.junit.JUnitRunner
import org.scalatest.{BeforeAndAfterEach, FunSuite}

import java.io.File
import java.nio.file.Paths

@RunWith(classOf[JUnitRunner])
class AesTest extends FunSuite with BeforeAndAfterEach with SparkUDF {

  implicit val spark = SparkSession.builder().config("spark.master", "local").getOrCreate()

  ignore("Create key files") {
    val numberOfKeyFiles = 1
    for (i <- 0 until numberOfKeyFiles) {
      genKeyFile("key/key_" + i, i)
    }
  }

  ignore ("Encryption using Spark and decrypt locally") {
    val keyCache = cacheKeyFromFolders("key")
    val df = spark.read.format("csv").option("delimiter", "|").option("header", "true").load("src/test/resources/test_data.txt")
    val plainText = df.select("sin").where("name = 'will'").collect.map(row => row.getString(0)).head
    df.show

    val encryptDf = dsEncrypt(df, "sin" ,keyCache)
    encryptDf.show(false)
    val cipherText = encryptDf.select("sin").where("name = 'will'").collect.map(row => row.getString(0)).head

    println(s"The plain is ${plainText} while cipher is ${cipherText}")
    val decryptedText = AesUtil.decryptWithVer(cipherText, keyCache)
    assertEquals(plainText, decryptedText)
  }

  ignore ("Performance test - load data, encrypt and decrypt data.") {
    val df = spark.read.format("csv").option("delimiter", ",").option("header", "true").load("src/test/resources/mock_data_set.csv")
    spark.time(df.count)
    val keyCache = cacheKeyFromFolders("key")
    val encryptDf = dsEncrypt(df, "other", keyCache)
    val res = dsDecrypt(encryptDf, "other", keyCache)
    spark.time(println("count = " + res.count))
  }

  test ("Test spark decryption and encryption") {
    val df = spark.read.format("csv").option("delimiter", "|").option("header", "true").load("src/test/resources/test_data.txt")
    val keyCache = cacheKeyFromFolders("key")

    val encryptDf = dsEncrypt(df, "sin,name", keyCache)
    encryptDf.show(false)

    val decryptDf = dsDecrypt(encryptDf, "sin,name", keyCache)
    decryptDf.show(false)
  }

  ignore("encryption using pass files local apps") {
    val input = "921-090-098"
    val keyCache = cacheKeyFromFolders("key")

    // encrypt the data
    val cipherText = AesUtil.encryptWithVer(input, keyCache)
    // decrypt the data
    val plainText = AesUtil.decryptWithVer(cipherText, keyCache)
    assertEquals(input, plainText)
  }

  ignore("encryption with string") {
    val input = "921-090-098"
    val key = AesUtil.generateKey(128)
    val ivParameterSpec = AesUtil.generateIv

    // when
    val cipherText = AesUtil.encrypt(input, key, ivParameterSpec)
    val plainText = AesUtil.decrypt(cipherText, key, ivParameterSpec)

    // then
    assertEquals(input, plainText)
  }

  ignore("encryption on files") {
    val key = AesUtil.generateKey(128)
    val ivParameterSpec = AesUtil.generateIv
    val inputFile = Paths.get("src/test/resources/test_data.txt").toFile
    val encryptedFile = new File("classpath:test_data.encrypted")
    val decryptedFile = new File("document.decrypted")

    // when
    AesUtil.encryptFile(key, ivParameterSpec, inputFile, encryptedFile)
    AesUtil.decryptFile(key, ivParameterSpec, encryptedFile, decryptedFile)

    // then
    //assertThat(inputFile).hasSameTextualContentAs(decryptedFile);
    encryptedFile.delete
    decryptedFile.delete
  }

  ignore("encryption with password") {
    // given
    val plainText = "921-090-098"
    val password = "test"
    val salt = "12345678"
    val ivParameterSpec = AesUtil.generateIv
    val key = AesUtil.getKeyFromPassword(password, salt)

    // when
    val cipherText = AesUtil.encryptPasswordBased(plainText, key, ivParameterSpec)
    val decryptedCipherText = AesUtil.decryptPasswordBased(cipherText, key, ivParameterSpec)

    // then
    assertEquals(plainText, decryptedCipherText)
  }
}
