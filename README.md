<p align="left"><img src="./src/main/resources/aes-logo.png" width="150"></p>

Simple encryption leverages AES algorithm to encrypt and decrypt data.
It uses secret key, iv with proper padding for detailed implementation.

## Key Prepare
1. Generate security key with key folder and number of keys needed
```shell
java -jar simple_encryption.jar AESUtil dev 31
```
2. Distribute the file to hdfs and web server accessible locations

## Encryption from Application
1. Read all key files to keyCache with
```scala
cacheKeyFromFolders("key", keyCache)
```   
2. Encrypt the data with encryptWithVer which also decide with version to use
```scala
val cipherText = AesUtil.encryptWithVer(input, keyCache)
```

## Encryption from Spark
1. Cache the keyfiles and choose which key version to use with rules
2. Get the key and iv as string, then add it to the spark.config, such as sparkConf.set
3. Build spark session with the config
4. call encrypt(df, version, key, iv) to encrypt the dataframe

## Decryption from Applications
1. Read all key files to keyCache with
```scala
val keyCache = new java.util.HashMap[String, Array[Byte]]()
cacheKeyFromFolders("key", keyCache)
```   
2. Call decryptWithVer(cipher, keyCache) to decrypt the data
```scala
val plainText = AesUtil.decryptWithVer(cipherText, keyCache)
```

## Key Rotation
1. The key can rotate from the encryption side as follows

    | rotate rule   | comments      |
    | ------------- |:-------------| 
    | `always `     | rotate keys for every run | 
    | `day `        | rotate keys on every day | 
    | `month `      | rotate keys on every month, default | 
    | `year `       | rotate keys on every year | 

2. Once all keys are cached, decryption works all the time.
3. If keys are destroyed, the cache keys should be removed carefully (make sure not being used on history data).
This usually applies to your data has retention period.
4. If new keys are added, do not reuse the old version as follows.
It creates additional 5 keys starting from version 31
```java
java -jar simple_encryption.jar AESUtil dev 5 31 
```
   
