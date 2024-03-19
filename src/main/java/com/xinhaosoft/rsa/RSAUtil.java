package com.xinhaosoft.rsa;

import cn.hutool.core.codec.Base64;
import cn.hutool.crypto.PemUtil;
import com.xinhaosoft.utils.PEMUtil;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Slf4j
public class RSAUtil {
    /**
     * 生成RSA 公私钥,可选长度为1025,2048位.
     */
    public static KeyPair generateRsaKey(int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(keySize, new SecureRandom());
        // 生成一个密钥对，保存在keyPair中

        return keyPairGen.generateKeyPair();
    }
    public static String rsaPublicKeyPem(PublicKey publicKey){
        return PEMUtil.formatPublicKeyPem( publicKey.getEncoded());
    }
    public static String rsaPrivateKeyPem(PrivateKey privateKey){
        return PEMUtil.formatPrivateKeyPem( privateKey.getEncoded());
    }

    public static PublicKey analysisRSAPublicKey(byte[] encoded) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encoded);
        return keyFactory.generatePublic(publicKeySpec);
    }

    public static PublicKey analysisRSAPublicKey(String pem) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
        return analysisRSAPublicKey(Base64.decode(pem.replaceAll(".*BEGIN.*?.*|.*END.*?.*", "")));
    }

    public static PublicKey analysisRSAPublicKey(File file) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
        try (InputStream inputStream = Files.newInputStream(file.toPath())) {
            return analysisRSAPublicKey(PemUtil.readPem(inputStream));
        }
    }

    public static PublicKey analysisRSAPublicKey(InputStream inputStream) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
        return analysisRSAPublicKey(PemUtil.readPem(inputStream));
    }


    public static PrivateKey analysisRSAPrivateKey(byte[] encoded) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(encoded);
        return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
    }

    public static PrivateKey analysisRSAPrivateKey(String pem) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
        return analysisRSAPrivateKey(Base64.decode(pem.replaceAll(".*BEGIN.*?.*|.*END.*?.*", "")));
    }

    public static PrivateKey analysisRSAPrivateKey(File file) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
        try (InputStream inputStream = Files.newInputStream(file.toPath())) {
            return analysisRSAPrivateKey(PemUtil.readPem(inputStream));
        }
    }

    public static PrivateKey analysisRSAPrivateKey(InputStream inputStream) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
        return analysisRSAPrivateKey(PemUtil.readPem(inputStream));
    }


}
