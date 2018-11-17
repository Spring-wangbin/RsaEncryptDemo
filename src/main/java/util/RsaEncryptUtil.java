package util;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Properties;

import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * RSA非对称加密解密工具类
 *
 * @ClassName RsaEncryptUtil
 * @content
 */
public class RsaEncryptUtil {

    /** */
    /**
     * 加密算法RSA
     */
    public static final String KEY_ALGORITHM = "RSA";// RSA/ECB/PKCS1Padding

    /**
     * String to hold name of the encryption padding.
     */
    public static final String PADDING = "RSA/NONE/PKCS1Padding";// RSA/NONE/NoPadding

    /**
     * String to hold name of the security provider.
     */
    public static final String PROVIDER = "BC";

    /** */
    /**
     * 签名算法
     */
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

    /** */
    /**
     * 获取公钥的key
     */
    private static final String PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqmzbmqAQvAdFm13tRuBpWy32Viw6ffplBrbEKX6Bpqvqq71gxFBs1/D2eNCAxxh3d+CMfDP7/1F5k8JoTBXpM5QTbrt+oX0jSPGqgy8szuB/49BqYZqYjN/76k3/53YTWWtwn6SIDdGZ8sr7g5LjJbIyPPNrhW7zpUusSQhP5EwIDAQAB";

    /** */
    /**
     * 获取私钥的key
     */
    private static final String PRIVATE_KEY = "MIICXQIBAAKBgQCqmzbmqAQvAdFm13tRuBpWy32Viw6ffplBrbEKX6Bpqvqq71gxFBs1/D2eNCAxxh3d+CMfDP7/1F5k8JoTBXpM5QTbrt+oX0jSPGqgy8szuB/49BqYZqYjN/76k3/53YTWWtwn6SIDdGZ8sr7g5LjJbIyPPNrhW7zpUusSQhP5EwIDAQABAoGAJ/WO2FuGD1SHrWTPF4bddHLZCUu2sxi94KpECz/2nIlViO/iYixpay2XaRSgbcgPeswBveYXW+hr64yHKelgiXw73FRln2I3HmkLJYeTdZMhHxPLlp8CgyxUjlWIh3N9Gt0q+u3rEmVPE65Dmvy21Kth9kbjCfEdbaBn5AnO+5ECQQDSst9sK0WR9scjbjlvkK9nNF0xq+wCT0rhiiFIWaQlYm2S2jjUrMPqdVGJMCSpglPx1tXh4zQRkMDraCB1r7M3AkEAz0mal7o6C3xk0enqXenHSIDV4c7t26GfwOWcc9QZJW38Z/sguwh43qw1C+IrMr5bjxRKka5hzgCM5+cz0CTPBQJBANCGgUKPzOm5/7pcE3IMEtykYXuQeCKNEUIIMApn1WG+eU12tfoeBkPb2ldZE1/EAYp+oe1OrLCZv6T7x+xReJ8CQGjxL4XfLyG/gV9QmGmhQFXxe9bNJ1iJE9LZrAJr/6sWarHNzr1Bxced0WFJyGrxOnNOZ44nhbaAStXhFDctW20CQQCpG0xHvRPEoyVqESI4simzcavHD8J1DJpRdz8EuxapZlDjNOf6PxeBUZKvbdLIfLIJGpGBQkqiC3+YTIcHW41w";

    /** */
    /**
     * RSA最大加密明文大小
     */
    private static final int MAX_ENCRYPT_BLOCK = 117;

    /** */
    /**
     * RSA最大解密密文大小
     */
    private static final int MAX_DECRYPT_BLOCK = 128;

    /*
     * 公钥加密
     */
    public static String encryptByPublicKey(String str) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        Cipher cipher = Cipher.getInstance(PADDING, PROVIDER);

        // 获得公钥
        Key publicKey = getPublicKey();

        // 用公钥加密
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        // 读数据源
        byte[] data = str.getBytes("UTF-8");

        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();

        return Base64Util.encode(encryptedData);
    }

    /**
     * 私钥加密
     *
     * @param str
     * @return
     * @throws Exception
     * @author kokJuis
     * @date 2016-4-7 下午12:53:15
     * @comment
     */
    public static String encryptByPrivateKey(String str) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        Cipher cipher = Cipher.getInstance(PADDING, PROVIDER);

        // 获得私钥
        Key privateKey = getPrivateKey();

        // 用私钥加密
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        // 读数据源
        byte[] data = str.getBytes("UTF-8");

        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();

        return Base64Util.encode(encryptedData);
    }

    /*
     * 公钥解密
     */
    public static String decryptByPublicKey(String str) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        Cipher cipher = Cipher.getInstance(PADDING, PROVIDER);

        // 获得公钥
        Key publicKey = getPublicKey();

        // 用公钥解密
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        // 读数据源
        byte[] encryptedData = Base64Util.decode(str);

        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher
                        .doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher
                        .doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();

        return new String(decryptedData, "UTF-8");
    }

    /*
     * 私钥解密
     */
    public static String decryptByPrivateKey(String str) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        Cipher cipher = Cipher.getInstance(PADDING, PROVIDER);
        // 得到Key
        Key privateKey = getPrivateKey();
        // 用私钥去解密
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        // 读数据源
        byte[] encryptedData = Base64Util.decode(str);

        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher
                        .doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher
                        .doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();

        // 二进制数据要变成字符串需解码
        return new String(decryptedData, "UTF-8");
    }

    /**
     * 从文件中读取公钥
     *
     * @return
     * @throws Exception
     * @author kokJuis
     * @date 2016-4-6 下午4:38:22
     * @comment
     */
    private static Key getPublicKey() throws Exception {
//		InputStream stream = Thread.currentThread().getContextClassLoader()
//				.getResourceAsStream("rsa_key.properties");
//		Properties properties = new Properties();
//		properties.load(stream);
//
//		String key = properties.getProperty(PUBLIC_KEY);
        String key = PUBLIC_KEY;
        byte[] keyBytes;
        keyBytes = Base64Util.decode(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    /**
     * 从文件中读取公钥String
     *
     * @return
     * @throws Exception
     * @author kokJuis
     * @date 2016-4-6 下午4:38:22
     * @comment
     */
    public static String getStringPublicKey(){
//		InputStream stream = Thread.currentThread().getContextClassLoader()
//				.getResourceAsStream("rsa_key.properties");
//		Properties properties = new Properties();
//		properties.load(stream);
//
//		String key = properties.getProperty(PUBLIC_KEY);

        return PUBLIC_KEY;
    }

    public static String getStringPrivateKey(){
//		InputStream stream = Thread.currentThread().getContextClassLoader()
//				.getResourceAsStream("rsa_key.properties");
//		Properties properties = new Properties();
//		properties.load(stream);
//
//		String key = properties.getProperty(PUBLIC_KEY);

        return PRIVATE_KEY;
    }

    /**
     * 获取私钥
     *
     * @return
     * @throws Exception
     * @author kokJuis
     * @date 2016-4-7 上午11:46:12
     * @comment
     */
    private static Key getPrivateKey() throws Exception {

//		InputStream stream = Thread.currentThread().getContextClassLoader()
//				.getResourceAsStream("rsa_key.properties");
//		Properties properties = new Properties();
//		properties.load(stream);
//
//		String key = properties.getProperty(PRIVATE_KEY);
        String key = PRIVATE_KEY;
        byte[] keyBytes;
        keyBytes = Base64Util.decode(key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

}
