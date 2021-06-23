package com.datafibers.aes

import com.google.gson.JsonObject

import java.util.Random

/**
 * This is KES/MinIO simulation.
 * KES sends two keys (index_key, secret_key)
 * plaintext is used for encryption
 * ciphertext is kept with cipher data and used for looking up secret key for decryption
 */
object FakeKes {

  val keys = Map(
    "ciphertext000" -> "plaintext000", "ciphertext001" -> "plaintext001", "ciphertext002" -> "plaintext002",
    "ciphertext003" -> "plaintext003", "ciphertext004" -> "plaintext004", "ciphertext005" -> "plaintext005"
  )

  def generateKesKeys() = {
    val index = "ciphertext00" + new Random().nextInt(keys.keySet.size)
    val response = new JsonObject
    response.addProperty("plaintext", keys.getOrElse(index, ""))
    response.addProperty("ciphertext", index)
    response
  }

  def fetchKesSecret(indexKey: String) = {
    val response = new JsonObject
    response.addProperty("plaintext", keys.getOrElse(indexKey, ""))
    response.addProperty("ciphertext", indexKey)
    response
  }

  // Main method
  def main(args: Array[String]) {
    println(generateKesKeys)
    println(fetchKesSecret("ciphertext001"))
  }
}
