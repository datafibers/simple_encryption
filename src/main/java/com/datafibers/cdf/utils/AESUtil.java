package com.datafibers.cdf.utils;

import com.sun.crypto.provider.SunJCE;
import org.apache.commons.lang3.StringUtils;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.lang.reflect.Array;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AESUtil {

    private final static Logger logger = Logger.getLogger(AESUtil.class.getName());

    private static byte[] concatenate(final byte[] a, final byte[] b, final byte[] c) {
        int aLen = a.length;
        int bLen = b.length;
        int cLen = c.length;
        byte[] all = (byte[]) Array.newInstance(byte.class, aLen + bLen + cLen);
        System.arraycopy(a, 0, all, 0, aLen);
        System.arraycopy(b, 0, all, aLen, bLen);
        System.arraycopy(c, 0, all, bLen, cLen);
        return all;
    }

    public static String encrypt(String algorithm, String input, SecretKey key, IvParameterSpec iv)
        throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
        InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String algorithm, String cipherText, SecretKey key, IvParameterSpec iv)
        throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
        InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }

    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(PasswordUtilConstant.DEFAULT_KEY_ALGORITHM);
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    public static SecretKey getKeyFromPassword(String password, String salt)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        // 128 -> 256
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 128);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
            .getEncoded(), "AES");
        return secret;
    }

    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[PasswordUtilConstant.DEFAULT_CIPHER_ALGORITHM_BLOCK_SIZE];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static void genKeyFile (String keyFileName, int version) {
        try {
            SecretKey localSecretKey = generateKey(PasswordUtilConstant.DEFAULT_AES_KEY_LENGTH);
            byte[] arrayOfByte = localSecretKey.getEncoded();
            // generate vi
            byte[] iv = generateIv().getIV();
            // combine version 5*8, key, and iv
            byte[] keyByte = concatenate(StringUtils.leftPad(String.valueOf(version), 5, "0").getBytes(), arrayOfByte, iv);
            Base64.Encoder localBASE64Encoder = Base64.getEncoder();
            try {
                PrintWriter localPrintWriter = new PrintWriter(new BufferedWriter(new FileWriter(keyFileName)));
                localPrintWriter.println(new String(localBASE64Encoder.encode(keyByte)));
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

    public static void encryptFile(String algorithm, SecretKey key, IvParameterSpec iv,
        File inputFile, File outputFile) throws IOException, NoSuchPaddingException,
        NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
        BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
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

    public static void decryptFile(String algorithm, SecretKey key, IvParameterSpec iv,
        File encryptedFile, File decryptedFile) throws IOException, NoSuchPaddingException,
        NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
        BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
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

    public static SealedObject encryptObject(String algorithm, Serializable object, SecretKey key,
        IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
        InvalidAlgorithmParameterException, InvalidKeyException, IOException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        SealedObject sealedObject = new SealedObject(object, cipher);
        return sealedObject;
    }

    public static Serializable decryptObject(String algorithm, SealedObject sealedObject, SecretKey key,
        IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
        InvalidAlgorithmParameterException, InvalidKeyException, ClassNotFoundException,
        BadPaddingException, IllegalBlockSizeException, IOException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        Serializable unsealObject = (Serializable) sealedObject.getObject(cipher);
        return unsealObject;
    }

    public static String encryptPasswordBased(String plainText, SecretKey key, IvParameterSpec iv)
        throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
        InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(PasswordUtilConstant.DEFAULT_CIPHER_PADDING_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return Base64.getEncoder()
            .encodeToString(cipher.doFinal(plainText.getBytes()));
    }

    public static String decryptPasswordBased(String cipherText, SecretKey key, IvParameterSpec iv)
        throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
        InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(PasswordUtilConstant.DEFAULT_CIPHER_PADDING_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return new String(cipher.doFinal(Base64.getDecoder()
            .decode(cipherText)));
    }

    public static void main(final String[] args) {
        if (args.length < 2) {
            logger.info("Usage: java AESUtil <key file path> <number of keys>");
            System.exit(0);
        }

        for (int i = 0; i < Integer.parseInt(args[1]); i++) {
            genKeyFile(args[0] + i, i);
        }
    }

}
