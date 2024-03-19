package com.xinhaosoft.sm2;

import cn.hutool.core.codec.Base64;
import cn.hutool.crypto.PemUtil;
import com.xinhaosoft.utils.PEMUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Slf4j
public class SM2Util {
    public static KeyPair generateRsaKey() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC",  new BouncyCastleProvider());
        // 定义SM2曲线参数规范
        //  sect283r1   sm2p256v1
        ECParameterSpec sm2Spec = ECNamedCurveTable.getParameterSpec("sm2p256v1");
        keyPairGen.initialize(sm2Spec, new SecureRandom());
        // 生成一个密钥对，保存在keyPair中
        return keyPairGen.generateKeyPair();
    }

    public static String sm2PublicKeyPem(PublicKey publicKey) {
        return PEMUtil.formatPublicKeyPem(publicKey.getEncoded());
    }

    public static String sm2PrivateKeyPem(PrivateKey privateKey) {
        return PEMUtil.formatPrivateKeyPem(privateKey.getEncoded());
    }

    public static PublicKey analysisSM2PublicKey(byte[] encoded) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("EC",  new BouncyCastleProvider());
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encoded);
        return keyFactory.generatePublic(publicKeySpec);
    }

    public static PublicKey analysisSM2PublicKey(String pem) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
        return analysisSM2PublicKey(Base64.decode(pem.replaceAll(".*BEGIN.*?.*|.*END.*?.*", "")));
    }

    public static PublicKey analysisSM2PublicKey(File file) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
        try (InputStream inputStream = Files.newInputStream(file.toPath())) {
            return analysisSM2PublicKey(PemUtil.readPem(inputStream));
        }
    }

    public static PublicKey analysisSM2PublicKey(InputStream inputStream) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
        return analysisSM2PublicKey(PemUtil.readPem(inputStream));
    }


    public static PrivateKey analysisSM2PrivateKey(byte[] encoded) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("EC",  new BouncyCastleProvider());
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(encoded);
        return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
    }

    public static PrivateKey analysisSM2PrivateKey(String pem) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
        return analysisSM2PrivateKey(Base64.decode(pem.replaceAll(".*BEGIN.*?.*|.*END.*?.*", "")));
    }

    public static PrivateKey analysisSM2PrivateKey(File file) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
        try (InputStream inputStream = Files.newInputStream(file.toPath())) {
            return analysisSM2PrivateKey(PemUtil.readPem(inputStream));
        }
    }

    public static PrivateKey analysisSM2PrivateKey(InputStream inputStream) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
        return analysisSM2PrivateKey(PemUtil.readPem(inputStream));
    }


}
