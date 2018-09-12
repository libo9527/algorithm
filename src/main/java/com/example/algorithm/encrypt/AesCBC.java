package com.example.algorithm.encrypt;

import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidParameterSpecException;

/**
 * <p>
 * 高级加密标准（英语：Advanced Encryption Standard，缩写：AES）
 * </p>
 * 密码分组链接模式（Cipher Block Chaining (CBC)）
 * 这种模式是先将明文切分成若干小段，然后每一小段与初始块或者上一段的密文段进行异或运算后，再与密钥进行加密。
 *
 * @Auther： libo
 * @date： 2018/9/12:21:52
 */
@Slf4j
public class AesCBC {

    private static final String CHARACTER_SET = "UTF-8";
    private static final String ALGORITHM_TYPE = "AES";
    private static final String AES_CBC_PKCS5_PADDING = "AES/CBC/PKCS5Padding";

    static {
        //BouncyCastle是一个开源的加解密解决方案，主页在http://www.bouncycastle.org/
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * AES加密
     *
     * @param dataString     需要加密的字符串
     * @param key            秘钥
     * @param iv             偏移量
     * @param encodingFormat 编码字符集
     * @return
     * @throws Exception
     */
    public static String encrypt(String dataString, String key, String iv, String encodingFormat) throws Exception {

        //加密秘钥
        key = to128Bits(key);
        log.info("key={}",Base64.encodeBase64String(key.getBytes(CHARACTER_SET)));
        //偏移量
        iv = to128Bits(iv);
        log.info("iv={}", Base64.encodeBase64String(iv.getBytes(CHARACTER_SET)));

        Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5_PADDING);
        byte[] raw = key.getBytes();
        SecretKeySpec skeySpec = new SecretKeySpec(raw, ALGORITHM_TYPE);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());//使用CBC模式，需要一个向量iv，可增加加密算法的强度
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(dataString.getBytes(encodingFormat));
        return Base64.encodeBase64String(encrypted);//此处使用BASE64做转码。
    }

    /**
     * AES解密
     *
     * @param data           密文，被加密的数据
     * @param key            秘钥
     * @param iv             偏移量
     * @param encodingFormat 解密后的结果需要进行的编码
     * @return
     * @throws Exception
     */
    public static String decrypt(String data, String key, String iv, String encodingFormat) throws Exception {

        //被加密的数据
        byte[] dataByte = Base64.decodeBase64(data);
        //加密秘钥
        byte[] keyByte = Base64.decodeBase64(key);
        //偏移量
        byte[] ivByte = Base64.decodeBase64(iv);
        try {
            Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5_PADDING);
            SecretKeySpec spec = new SecretKeySpec(keyByte, ALGORITHM_TYPE);
            AlgorithmParameters parameters = AlgorithmParameters.getInstance(ALGORITHM_TYPE);
            parameters.init(new IvParameterSpec(ivByte));
            cipher.init(Cipher.DECRYPT_MODE, spec, parameters);// 初始化
            byte[] resultByte = cipher.doFinal(dataByte);
            if (null != resultByte && resultByte.length > 0) {
                String result = new String(resultByte, encodingFormat);
                return result;
            }
            return null;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidParameterSpecException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * JDK只支持AES-128加密，也就是密钥长度必须是128bit；参数为密钥key，key的长度小于16字符时用"0"补充，key长度大于16字符时截取前16位
     **/
    private static SecretKeySpec create128BitsKey(String key) {
        if (key == null) {
            key = "";
        }
        byte[] data = null;
        StringBuffer buffer = new StringBuffer(16);
        buffer.append(key);
        //小于16后面补0
        while (buffer.length() < 16) {
            buffer.append("0");
        }
        //大于16，截取前16个字符
        if (buffer.length() > 16) {
            buffer.setLength(16);
        }
        try {
            data = buffer.toString().getBytes(CHARACTER_SET);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return new SecretKeySpec(data, ALGORITHM_TYPE);
    }

    /**
     * 创建128位的偏移量，iv的长度小于16时后面补0，大于16，截取前16个字符;
     *
     * @param iv
     * @return
     */
    private static IvParameterSpec create128BitsIV(String iv) {
        if (iv == null) {
            iv = "";
        }
        byte[] data = null;
        StringBuffer buffer = new StringBuffer(16);
        buffer.append(iv);
        while (buffer.length() < 16) {
            buffer.append("0");
        }
        if (buffer.length() > 16) {
            buffer.setLength(16);
        }
        try {
            data = buffer.toString().getBytes(CHARACTER_SET);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return new IvParameterSpec(data);
    }

    /**
     * 转化为128位即16个字符的字符串，长度小于16字符时用"0"补充，长度大于16字符时截取前16位
     *
     * @param s
     * @return
     */
    private static String to128Bits(String s) {
        if (s == null) {
            s = "";
        }
        byte[] data = null;
        StringBuffer buffer = new StringBuffer(16);
        buffer.append(s);
        while (buffer.length() < 16) {
            buffer.append("0");
        }
        if (buffer.length() > 16) {
            buffer.setLength(16);
        }
        return buffer.toString();
    }
}
