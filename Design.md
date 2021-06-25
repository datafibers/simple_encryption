## KES/MinIO design

#### Spark Encryption
1. Fetch n keys from Kes based on rotation rules - create one roe df and do it once with map or udf
2. broadcast Kes pk and ck dataframe
3. join df with kes keys and apply udf for encryption and append ck by row

#### Spark Decryption
1. Split cipher column in df to cipher key and encrypted data
2. for each cipher key call/map usd to fetch plain text key from kes
3. join data df with plain text key df on cipher key
4. in the result df apply udf to decrypt cipher with plain text key
5. drop column, plain text key and cipher text key from df after decryption
