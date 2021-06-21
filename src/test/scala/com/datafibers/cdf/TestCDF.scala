package com.datafibers.cdf

import com.datafibers.cdf.utils.AesUtil.{cacheKeyFromFile, cacheKeyFromFolders, genKeyFile, getIvFromPassByte, getKeyFromPassByte, getKeyVersionByRule}
import com.datafibers.cdf.utils.{AesUtil, DFCompare, PasswordUtilConstant, SetupFunc, SourceToDS}
import org.apache.commons.io.FileUtils
import org.apache.spark.sql.{SaveMode, SparkSession}
import org.junit.Assert.assertEquals
import org.junit.runner.RunWith
import org.scalatest.junit.JUnitRunner
import org.scalatest.{BeforeAndAfterEach, FunSuite}

import java.io.File
import java.nio.file.Paths

@RunWith(classOf[JUnitRunner])
class TestCDF extends FunSuite with SourceToDS with BeforeAndAfterEach with SetupFunc {

  implicit val spark = sparkEnvInitialization(this.getClass.getName)
  System.setProperty("DE_OUTPUT_ROOT_PATH", "output")
  System.setProperty("DE_LOG_ROOT_PATH", "output/log")

  val outputFileDirectory = System.getProperty("DE_OUTPUT_ROOT_PATH")
  FileUtils.deleteDirectory(new File(outputFileDirectory))

  ignore ("row count check using empty yml config") {
    val appCode = "empty-cob"
    val args = Array(s"src/main/resources/conf/app_${appCode}.yml", "cob")
    val config = setAppConfig(args)
    spark.sql("create database if not exists kdb_uk_prod")
    spark.sql("use kdb_uk_prod")
    readDataFromFileAsDF("csv", "src/test/resources/data/kdb_uk_prod/spot_rate")
      .write.mode(SaveMode.Overwrite).saveAsTable("spot_rate")

    setAppRun(args, spark)
    val actualDFCnt = readDataFromFileAsDF(config.getOrElse("output_type", "").toString, outputFileDirectory).count
    val expectDFCnt = spark.sql("select * from kdb_uk_prod.spot_rate").count
    spark.sql("show databases")
    spark.sql("select count(*) as cnt from kdb_uk_prod.spot_rate").show
    assert(actualDFCnt === expectDFCnt)
    spark.sql("drop database if exists kdb_uk_prod cascade")
  }

  ignore ("row count check with init sql and ingested parameters") {
    val appCode = "file-cob"
    val cob = "20201019"
    System.setProperty("cob", s"${cob}") // since the yml file contains ${cob}, it should be in sys.properties to substitute
    val args = Array(s"src/main/resources/conf/app_${appCode}.yml", s"${cob},input1,input2") // here the additional parameters are ingested to sql
    setAppRun(args, spark)
    val actualDF = spark.read.parquet(s"output/direct-insert/run_date=${cob}")
    val expectDF = readDataFromFileAsDF("csv", s"src/test/resources/data/ftek_us_prod/${cob}")
    val para_1 = actualDF.select("para_1").collect.map(row => row.getString(0)).head
    val para_2 = actualDF.select("para_2").collect.map(row => row.getString(0)).head
    assert(actualDF.count === expectDF.count && para_1 === "input1" && para_2 === "input2")
  }

  ignore ("comparing files") {
    DFCompare.main(
      Array("src/test/resources/data/data_compare/a", "src/test/resources/data/data_compare/b", "col1",
        "1.0,col4,2,3", System.getProperty("DE_OUTPUT_ROOT_PATH") + "/compare_result")
    )
  }

  test ("encryption with string") {
    val input = "921-090-098"
    val key = AesUtil.generateKey(128)
    val ivParameterSpec = AesUtil.generateIv
    val algorithm = "AES/CBC/PKCS5Padding"

    // when
    val cipherText = AesUtil.encrypt(input, key, ivParameterSpec)
    val plainText = AesUtil.decrypt(cipherText, key, ivParameterSpec)

    // then
    assertEquals(input, plainText)
  }

  test ("encryption on files") {
    val key = AesUtil.generateKey(128)
    val ivParameterSpec = AesUtil.generateIv
    val inputFile = Paths.get("src/test/resources/sin.txt").toFile
    val encryptedFile = new File("classpath:baeldung.encrypted")
    val decryptedFile = new File("document.decrypted")

    // when
    AesUtil.encryptFile(key, ivParameterSpec, inputFile, encryptedFile)
    AesUtil.decryptFile(key, ivParameterSpec, encryptedFile, decryptedFile)

    // then
    //assertThat(inputFile).hasSameTextualContentAs(decryptedFile);
    encryptedFile.delete
    decryptedFile.delete
  }

  test ("encryption with password") {
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

  test ("encryption using pass files local apps") {
    val input = "921-090-098"
    val numberOfKeyFiles = 30
    val keyCache = new java.util.HashMap[String, Array[Byte]]()

    // create key files
    for (i <- 0 until numberOfKeyFiles) {
      genKeyFile("key/key_" + i, i)
    }

    // load all keys to cache
    cacheKeyFromFolders("key", keyCache)

    // encrypt the data
    val cipherText = AesUtil.encryptWithVer(input, keyCache)
    // decrypt the data
    val plainText = AesUtil.decryptWithVer(cipherText, keyCache)
    assertEquals(input, plainText)
  }

}
