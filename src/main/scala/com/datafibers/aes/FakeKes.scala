package com.datafibers.aes

import java.util.Random

/**
 * This is KES/MinIO simulation.
 * KES sends two keys (index_key, secret_key)
 * secret_key is used for encryption
 * index_key is kept with cipher data and used for looking up secret key for decryption
 */
object FakeKes {

  val keys = Map("index_key000" -> "secret_key000", "index_key001" -> "secret_key001", "index_key002" -> "secret_key002")

  def getKesKeys() = {
    val index = "index_key00" + new Random().nextInt(keys.keySet.size)
    index + "," + keys.getOrElse(index, "")
  }

  def getKesSecret(secretKey: String) = {
    keys.getOrElse(secretKey, "")
  }

  // Main method
  def main(args: Array[String]) {
    println(getKesKeys)
    println(getKesSecret("index_key001"))
  }
}
