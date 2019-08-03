package com.example.rsa;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.IntRange;
import androidx.annotation.NonNull;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

public class RSAUtil {

    public static final String ANDROID_TRANSFORMATION   = "RSA/NONE/NoPadding"; //服务端也要这样
    public static final String JAVA_TRANSFORMATION      = "RSA/ECB/PKCS1Padding";

    public static final int DEFAULT_KEY_SIZE    = 2048;
    public static final int MAX_DECRYPT_SIZE    = DEFAULT_KEY_SIZE / 8;     //当前秘钥支持[解密]的最大字节数
    public static final int MAX_ENCRYPT_SIZE    = MAX_DECRYPT_SIZE - 11;    //当前秘钥支持[加密]的最大字节数

    public static KeyPair generateRSAKeyPair(@IntRange(from = 1,to = 4096) int keyLength) {
        try {
            final String RSA = "RSA";

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keyLength);
            return kpg.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static KeyPair init(@IntRange(from = 1,to = 4096) int keyLength) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keyLength);
            KeyPair keyPair =  kpg.genKeyPair();
            return keyPair;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
    // 公钥加密,支持分段。最大 MAX_ENCRYPT_SIZE 字节
    public static byte[] encryptByPublicKey(@NonNull byte[] data,RSAPublicKey key) throws Exception {

        // 加密数据
        Cipher cipher = Cipher.getInstance(ANDROID_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        int inOffset = 0,outOffset = 0;

        int olen = cipher.getOutputSize(data.length);
        byte output[] = new byte[olen];
        Log.e("RSAUtil", "encryptByPublicKey: data.len = " + data.length + " outLen = " + olen);

        int loop = data.length / MAX_ENCRYPT_SIZE;

        for (int i = 0 ; i < loop; ++i){
            int inLen = MAX_ENCRYPT_SIZE;
            int outLen = cipher.update(data,inOffset,inLen,output,outOffset);
            Log.e("RSAUtil", "encryptByPublicKey: outLen = " + outLen + " inLen = " + inLen);
            inOffset += inLen;
            outOffset += outLen;
        }

        if (inOffset <= data.length){
            cipher.update(data,inOffset,data.length - inOffset,output,outOffset);
        }
        return cipher.doFinal();
    }


    // 私钥解密,支持分段。最大 MAX_DECRYPT_SIZE 字节
    public static byte[] decryptByPrivateKey(@NonNull byte[] encrypted,RSAPrivateKey key) throws Exception {

        // 解密数据
        Cipher cipher = Cipher.getInstance(ANDROID_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key);


        int inOffset = 0,outOffset = 0;

        int olen = cipher.getOutputSize(encrypted.length);
        byte output[] = new byte[olen];
        Log.e("RSAUtil", "decryptByPrivateKey: data.len = " + encrypted.length + " outLen = " + olen);

        int loop = encrypted.length / MAX_DECRYPT_SIZE;

        for (int i = 0 ; i < loop; ++i){
            int inLen = MAX_DECRYPT_SIZE;
            int outLen = cipher.update(encrypted,inOffset,inLen,output,outOffset);
            Log.e("RSAUtil", "decryptByPrivateKey: outLen = " + outLen + " inLen = " + inLen);
            inOffset += inLen;
            outOffset += outLen;
        }

        if (inOffset <= encrypted.length){
            cipher.update(encrypted,inOffset,encrypted.length - inOffset,output,outOffset);
        }

        return cipher.doFinal();
    }


    // 私钥加密,支持分段。最大 MAX_ENCRYPT_SIZE 字节
    public static byte[] encryptByPrivateKey(@NonNull byte[] data,RSAPrivateKey key) throws Exception {

        // 数据加密
        Cipher cipher = Cipher.getInstance(ANDROID_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        int inOffset = 0,outOffset = 0;

        int olen = cipher.getOutputSize(data.length);
        byte output[] = new byte[olen];
        Log.e("RSAUtil", "encryptByPrivateKey: data.len = " + data.length + " outLen = " + olen);

        int loop = data.length / MAX_ENCRYPT_SIZE;

        for (int i = 0 ; i < loop; ++i){
            int inLen = MAX_ENCRYPT_SIZE;
            int outLen = cipher.update(data,inOffset,inLen,output,outOffset);
            Log.e("RSAUtil", "encryptByPrivateKey: outLen = " + outLen + " inLen = " + inLen);
            inOffset += inLen;
            outOffset += outLen;
        }

        if (inOffset <= data.length){
            cipher.update(data,inOffset,data.length - inOffset,output,outOffset);
        }
        return cipher.doFinal();
    }

    // 公钥解密,支持分段。最大 MAX_DECRYPT_SIZE 字节
    public static byte[] decryptByPublicKey(@NonNull byte[] data,RSAPublicKey key) throws Exception {

        // 数据解密
        Cipher cipher = Cipher.getInstance(ANDROID_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key);

        int inOffset = 0,outOffset = 0;

        int olen = cipher.getOutputSize(data.length);
        byte output[] = new byte[olen];
        Log.e("RSAUtil", "decryptByPublicKey: data.len = " + data.length + " outLen = " + olen);

        int loop = data.length / MAX_DECRYPT_SIZE;

        for (int i = 0 ; i < loop; ++i){
            int inLen = MAX_DECRYPT_SIZE;
            int outLen = cipher.update(data,inOffset,inLen,output,outOffset);
            Log.e("RSAUtil", "decryptByPublicKey: outLen = " + outLen + " inLen = " + inLen);
            inOffset += inLen;
            outOffset += outLen;
        }

        if (inOffset <= data.length){
            cipher.update(data,inOffset,data.length - inOffset,output,outOffset);
        }
        return cipher.doFinal();
    }

    // 签名
    public static byte[] sign(@NonNull byte [] data,RSAPrivateKey key) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(key);
        signature.update(data);
        return signature.sign();
    }

    // 验签
    public static boolean verify(byte [] data, byte [] signed,RSAPublicKey key) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(key);
        signature.update(data);
        return signature.verify(signed);
    }

	// 通过公钥byte[]将公钥还原
	public static PublicKey getPublicKey(@NonNull byte[] keyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
	    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	    PublicKey publicKey = keyFactory.generatePublic(keySpec);
	    return publicKey;
	}

	// 通过私钥byte[]将公钥还原
	public static PrivateKey getPrivateKey(@NonNull byte[] keyBytes) throws NoSuchAlgorithmException,InvalidKeySpecException {
	    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
	    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	    PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
	    return privateKey;
	}

    // 打印公钥信息
    public static void printPublicKeyInfo(@NonNull RSAPublicKey publicKey){

        Log.e("RSAUtil", "-----------RSAPublicKey-----------");
        Log.e("RSAUtil", "publicKey = " + publicKey.toString());
        Log.e("RSAUtil", "Modulus.length =" + publicKey.getModulus().bitLength());
        Log.e("RSAUtil", "Modulus = " + publicKey.getModulus().toString());
        Log.e("RSAUtil", "PublicExponent.length = " + publicKey.getPublicExponent().bitLength());
        Log.e("RSAUtil", "PublicExponent = " + publicKey.getPublicExponent().toString());
    }

    // 打印私钥信息
    public static void printPrivateKeyInfo(@NonNull RSAPrivateKey privateKey) {

        Log.e("RSAUtil", "----------RSAPrivateKey-----------:");
        Log.e("RSAUtil", "privateKey = " + privateKey.toString());
        Log.e("RSAUtil", "Modulus.length = " + privateKey.getModulus().bitLength());
        Log.e("RSAUtil", "Modulus = " + privateKey.getModulus().toString());
        Log.e("RSAUtil", "PublicExponent.length = " + privateKey.getPrivateExponent().bitLength());
        Log.e("RSAUtil", "PublicExponent = " + privateKey.getPrivateExponent().toString());

    }

    // 从assets读取公钥、私钥 经base64编码的字符串。
    public static String loadKeyFromAssets(String file){
        Context context = RsaApp.context;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            InputStream is = context.getAssets().open(file);
            InputStreamReader ir = new InputStreamReader(is);
            BufferedReader br = new BufferedReader(ir);
            String line ;
            StringBuilder sb = new StringBuilder();
            while ((line = br.readLine()) != null){
                if (!line.startsWith("-----")){
                    sb.append(line);
                    baos.write(line.getBytes());
                }
            }
            Log.e("RSAUtil", "loadKeyFromAssets: key = " + sb.toString() );
            return sb.toString();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }


    private static String encodeBase64(byte[] data) {
        String b64 = Base64.encodeToString(data, Base64.DEFAULT);
        return b64;
    }

    private static byte[] decodeBase64(String b64) {
        byte[] ret = Base64.decode(b64, Base64.DEFAULT);
        return ret;
    }
}
