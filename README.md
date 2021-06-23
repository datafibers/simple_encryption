<p align="left"><img src="./src/main/resources/aes-logo.png" width="150"></p>

Simple encryption leverages AES algorithm to encrypt and decrypt data.
It uses secret key, iv with proper padding for detailed implementation.

## Key Prepare
1. Generate security key with key folder and number of keys needed
```shell
java -jar simple_encryption.jar AESUtil dev 31
```
2. Distribute the file to where application can access, such as HDFS or GitHub with Spring Cloud Config.

## Encryption and Decryption from Application
1. Read all key files to keyCache with encoded
```scala
val keyCache = cacheKeyFromFolders("key")
```   
2. Encrypt the data (string) with rule-based version of keys
```scala
val cipherText = AesUtil.encryptWithVer(input, keyCache)
```
3. Decrypt the data with the version of keys in cipher
```scala
val plainText = AesUtil.decryptWithVer(cipherText, keyCache)
```

## Encryption and Decryption from Spark
1. Cache the keyfiles and choose which key version to use with rules
```scala
val keyCache = cacheKeyFromFolders("key")
```
2. Encrypt the dataframe (df) string column with rule-based version of keys
```scala
val encryptDf = dsEncrypt(df, "email,address", keyCache)
```   
3. Decrypt the dataframe (encryptDf) with the version of keys in cipher
```scala
val decryptDf = dsDecrypt(encryptDf, "email,address", keyCache)
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
```shell
java -jar simple_encryption.jar AESUtil dev 5 31 
```

## Format
* The default key file format is version (3 byte), key (16 byte/128 bit), and iv (16 byte/128 bit).
* The cipher text format is key_version (3 byte), cipher text.

## TODO
- [ ] Add support to for key generation dynamically from DES/KMS
- [X] Add spark decryption function
- [X] Add performance test cases
