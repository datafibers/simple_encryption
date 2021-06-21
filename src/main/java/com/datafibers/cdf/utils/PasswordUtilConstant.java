package com.datafibers.cdf.utils;

public class PasswordUtilConstant {
    /**
     * key length = 128 bit/16 byte
     * iv block size is 16 byte
      */
    public static final int DEFAULT_AES_KEY_LENGTH = 128;
    public static final int DEFAULT_CIPHER_ALGORITHM_BLOCK_SIZE = 16;
    public static final String DEFAULT_KEY_ALGORITHM = "AES";
    public static final String DEFAULT_CIPHER_PADDING_ALGORITHM = "AES/CBC/PKCS5Padding";
    public static final int DEFAULT_KEY_VERSION_LENGTH = 3;
    public static final String DEFAULT_KEY_ROTATION_RULE = "month";
}
