package com.datafibers.cdf.utils;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.time.LocalDate;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author will
 */
public class AesUtil {

    private final static Logger logger = Logger.getLogger(AesUtil.class.getName());

    public static String encrypt(String input, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(PasswordUtilConstant.DEFAULT_CIPHER_PADDING_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    /**
     * ncrypt the data and add the key version to the encrypt data
     * @param input
     * @param key
     * @param iv
     * @param keyVer
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String encryptWithVer(String input, SecretKey key, IvParameterSpec iv, String keyVer)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(PasswordUtilConstant.DEFAULT_CIPHER_PADDING_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(ArrayUtils.addAll(keyVer.getBytes(), cipherText));
    }

    public static String encryptWithVer(String input, String keyVer, HashMap<String, byte[]> keyCache)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return encryptWithVer(input,
                getKeyFromPassByte(keyCache.get(keyVer)), getIvFromPassByte(keyCache.get(keyVer)), keyVer);
    }

    public static String encryptWithVer(String input, HashMap<String, byte[]> keyCache, String rule)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        String keyVer = getKeyVersionByRule(rule, keyCache);
        return encryptWithVer(input,
                getKeyFromPassByte(keyCache.get(keyVer)), getIvFromPassByte(keyCache.get(keyVer)), keyVer);
    }

    public static String encryptWithVer(String input, HashMap<String, byte[]> keyCache)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return encryptWithVer(input, keyCache, PasswordUtilConstant.DEFAULT_KEY_ROTATION_RULE);
    }

    public static String decrypt(String cipherText, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(PasswordUtilConstant.DEFAULT_CIPHER_PADDING_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }

    public static String decryptWithVer(String cipherText, HashMap<String, byte[]> keyCache)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] cipherTextDecoded = Base64.getDecoder().decode(cipherText);
        String keyVer = new String(Arrays.copyOf(cipherTextDecoded, PasswordUtilConstant.DEFAULT_KEY_VERSION_LENGTH));
        byte[] cipherTextWithoutVer = Arrays.copyOfRange(cipherTextDecoded, PasswordUtilConstant.DEFAULT_KEY_VERSION_LENGTH, cipherTextDecoded.length);
        Cipher cipher = Cipher.getInstance(PasswordUtilConstant.DEFAULT_CIPHER_PADDING_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, getKeyFromPassByte(keyCache.get(keyVer)), getIvFromPassByte(keyCache.get(keyVer)));
        byte[] plainText = cipher.doFinal(cipherTextWithoutVer);
        return new String(plainText);
    }

    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(PasswordUtilConstant.DEFAULT_KEY_ALGORITHM);
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        return generateKey(PasswordUtilConstant.DEFAULT_AES_KEY_LENGTH);
    }

    public static SecretKey getKeyFromPassword(String password, String salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        // 128 -> 256
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 128);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        return secret;
    }

    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[PasswordUtilConstant.DEFAULT_CIPHER_ALGORITHM_BLOCK_SIZE];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static void encryptFile(SecretKey key, IvParameterSpec iv,
                                   File inputFile, File outputFile) throws IOException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(PasswordUtilConstant.DEFAULT_CIPHER_PADDING_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream outputStream = new FileOutputStream(outputFile);
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                outputStream.write(output);
            }
        }
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes != null) {
            outputStream.write(outputBytes);
        }
        inputStream.close();
        outputStream.close();
    }

    public static void decryptFile(SecretKey key, IvParameterSpec iv,
                                   File encryptedFile, File decryptedFile) throws IOException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(PasswordUtilConstant.DEFAULT_CIPHER_PADDING_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        FileInputStream inputStream = new FileInputStream(encryptedFile);
        FileOutputStream outputStream = new FileOutputStream(decryptedFile);
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                outputStream.write(output);
            }
        }
        byte[] output = cipher.doFinal();
        if (output != null) {
            outputStream.write(output);
        }
        inputStream.close();
        outputStream.close();
    }

    public static SealedObject encryptObject(Serializable object, SecretKey key,
                                             IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, IOException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(PasswordUtilConstant.DEFAULT_CIPHER_PADDING_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        SealedObject sealedObject = new SealedObject(object, cipher);
        return sealedObject;
    }

    public static Serializable decryptObject(SealedObject sealedObject, SecretKey key,
                                             IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, ClassNotFoundException,
            BadPaddingException, IllegalBlockSizeException, IOException {
        Cipher cipher = Cipher.getInstance(PasswordUtilConstant.DEFAULT_CIPHER_PADDING_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        Serializable unsealObject = (Serializable) sealedObject.getObject(cipher);
        return unsealObject;
    }

    public static String encryptPasswordBased(String plainText, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(PasswordUtilConstant.DEFAULT_CIPHER_PADDING_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }

    public static String decryptPasswordBased(String cipherText, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(PasswordUtilConstant.DEFAULT_CIPHER_PADDING_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return new String(cipher.doFinal(Base64.getDecoder().decode(cipherText)));
    }

    public static void genKeyFile(String keyFileName, int version) {
        try {
            SecretKey localSecretKey = generateKey(PasswordUtilConstant.DEFAULT_AES_KEY_LENGTH);
            byte[] keyByte = localSecretKey.getEncoded();
            // generate vi
            byte[] iv = generateIv().getIV();
            byte[] versionByte = StringUtils.leftPad(String.valueOf(version), PasswordUtilConstant.DEFAULT_KEY_VERSION_LENGTH, "0").getBytes();
            // combine version, key, and iv
            byte[] passByte = ArrayUtils.addAll(ArrayUtils.addAll(versionByte, keyByte), iv);
            Base64.Encoder localBASE64Encoder = Base64.getEncoder();
            try {
                PrintWriter localPrintWriter = new PrintWriter(new BufferedWriter(new FileWriter(keyFileName)));
                localPrintWriter.println(new String(localBASE64Encoder.encode(passByte)));
                localPrintWriter.close();
            } catch (IOException ioe) {
                logger.log(Level.SEVERE, "Error: writing password file.", ioe);
                System.exit(1);
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error: cannot generate secret key", e);
            System.exit(2);
        }
    }

    public static void cacheKeyFromFile(final String pwdFilePath, HashMap<String, byte[]> hm) throws IOException {
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        byte[] versionByte = new byte[PasswordUtilConstant.DEFAULT_KEY_VERSION_LENGTH];
        try {
            Base64.Decoder localBASE64Decoder = Base64.getDecoder();
            BufferedReader localBufferedReader = new BufferedReader(new InputStreamReader(fs.open(new Path(pwdFilePath))));
            byte[] keyArrayOfByte = localBASE64Decoder.decode(localBufferedReader.readLine());
            versionByte = Arrays.copyOf(keyArrayOfByte, versionByte.length);
            localBufferedReader.close();
            hm.put(new String(versionByte), keyArrayOfByte);
        } catch (IOException ioe) {
            System.out.println("Error: cannot read from password file.");
        }
    }

    public static void cacheKeyFromFolders(final String pwdFileFolder, HashMap<String, byte[]> hm) throws IOException {
        Files.list(Paths.get(pwdFileFolder)).forEach(x -> {
            try {
                cacheKeyFromFile(x.toString(), hm);
            } catch (IOException ioe) {
                System.out.println("Error: cannot read from password file.");
            }
        });
    }

    public static SecretKeySpec getKeyFromPassByte(byte[] passByte) {
        byte[] versionByte = new byte[PasswordUtilConstant.DEFAULT_KEY_VERSION_LENGTH];
        byte[] keyByte = new byte[PasswordUtilConstant.DEFAULT_CIPHER_ALGORITHM_BLOCK_SIZE];
        keyByte = Arrays.copyOfRange(passByte, versionByte.length, versionByte.length + keyByte.length);
        SecretKeySpec keySpec = new SecretKeySpec(
                keyByte, 0, PasswordUtilConstant.DEFAULT_AES_KEY_LENGTH / 8,
                PasswordUtilConstant.DEFAULT_KEY_ALGORITHM);
        return keySpec;
    }

    public static IvParameterSpec getIvFromPassByte(byte[] passByte) {
        byte[] versionByte = new byte[PasswordUtilConstant.DEFAULT_KEY_VERSION_LENGTH];
        byte[] keyByte = new byte[PasswordUtilConstant.DEFAULT_CIPHER_ALGORITHM_BLOCK_SIZE];
        byte[] iv = new byte[PasswordUtilConstant.DEFAULT_CIPHER_ALGORITHM_BLOCK_SIZE];
        iv = Arrays.copyOfRange(passByte, versionByte.length + keyByte.length, versionByte.length + keyByte.length + iv.length);
        return new IvParameterSpec(iv);
    }

    public static String getKeyVersionByRule(String rule, HashMap<String, byte[]> hm) {
        String version = "000";
        LocalDate localDate = java.time.LocalDate.now();

        if (rule == "always") {
            version = hm.keySet().toArray()[new Random().nextInt(hm.keySet().toArray().length)].toString();
        } else if (rule == "day") {
            version = hm.keySet().toArray()[localDate.getDayOfMonth() % hm.keySet().toArray().length].toString();
        } else if (rule == "month") {
            version = hm.keySet().toArray()[localDate.getMonthValue() % hm.keySet().toArray().length].toString();
        } else if (rule == "year") {
            version = hm.keySet().toArray()[localDate.getYear() % hm.keySet().toArray().length].toString();
        }
        return version;
    }

    public static void main(final String[] args) throws IOException {
        if (args.length < 2 || Integer.parseInt(args[1]) > 999) {
            logger.info("Usage: java AESUtil <key file path> <number of keys, less than 1000> <start version, default 0");
            logger.info("To destroy the old key, we should remove them and use <start version> to generate new version of keys");
            System.exit(0);
        }
        int start = args.length == 3 ? Integer.parseInt(args[2]) : 0;
        Files.createDirectories(Paths.get(args[0]));

        for (int i = start; i < Integer.parseInt(args[1]); i++) {
            genKeyFile(args[0] + "/key_" + i, i);
        }
    }

}
