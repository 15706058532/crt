package com.xinhaosoft.cert;

import cn.hutool.core.codec.Base64;
import com.xinhaosoft.enums.AlgorithmEnum;
import com.xinhaosoft.utils.PEMUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.*;
import java.math.BigInteger;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

@Slf4j
public class CERTUtil {

    public static X509Certificate generateSelfSignedCertificate(X500Name issuerName, X500Name subjectName, PublicKey publicKey, PrivateKey privateKey, String signatureAlgorithm) throws OperatorCreationException, CertificateException {
        //颁发者
//        X500NameBuilder issuerBuilder = new X500NameBuilder(BCStyle.INSTANCE);
//        issuerBuilder.addRDN(BCStyle.C, "CN");
//        issuerBuilder.addRDN(BCStyle.ST, "陕西");
//        issuerBuilder.addRDN(BCStyle.L, "西安");
//        issuerBuilder.addRDN(BCStyle.O, "xinhao");
//        issuerBuilder.addRDN(BCStyle.OU, "yanfa");
//        issuerBuilder.addRDN(BCStyle.CN, "xinhao.com");
//        issuerBuilder.addRDN(BCStyle.E, "1@163.com");
//        X500Name issuerName = issuerBuilder.build();
        //主题(使用者)
//        X500NameBuilder subjectBuilder = new X500NameBuilder(BCStyle.INSTANCE);
//        subjectBuilder.addRDN(BCStyle.C, "CN");
//        subjectBuilder.addRDN(BCStyle.ST, "陕西");
//        subjectBuilder.addRDN(BCStyle.L, "西安");
//        subjectBuilder.addRDN(BCStyle.O, "xinhao");
//        subjectBuilder.addRDN(BCStyle.OU, "yanfa");
//        subjectBuilder.addRDN(BCStyle.CN, "xinhao.com");
//        subjectBuilder.addRDN(BCStyle.E, "1@163.com");
//        X500Name subjectName = subjectBuilder.build();

        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        //有效期开始时间现在
        Instant notBefore = Instant.now();
        //有效期结束时间一年后
        Instant notAfter = notBefore.plus(Duration.ofDays(365));
        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(
                issuerName, // 主题名称
                serialNumber, // 序列号
                Date.from(notBefore),// 有效期开始时间
                Date.from(notAfter), // 有效期结束时间
                subjectName, // 颁发者名称
                SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));// 公钥

        // 使用自己的私钥进行签名
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).build(privateKey);

        // 转换为 X509Certificate 对象
        return new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(certificateBuilder.build(signer));
    }

    public static X509Certificate generateSelfSignedCertificate(X500NameInfo issuerNameInfo, X500NameInfo subjectNameInfo, PublicKey publicKey, PrivateKey privateKey, String signatureAlgorithm) throws OperatorCreationException, CertificateException {
        return generateSelfSignedCertificate(issuerNameInfo.build(), subjectNameInfo.build(), publicKey, privateKey, signatureAlgorithm);
    }

    public static X509Certificate generateSelfSignedCertificate(X500NameInfo issuerNameInfo, X500NameInfo subjectNameInfo,  PublicKey publicKey, PrivateKey privateKey, AlgorithmEnum signatureAlgorithm) throws OperatorCreationException, CertificateException {
        return generateSelfSignedCertificate(issuerNameInfo.build(), subjectNameInfo.build(), publicKey, privateKey, signatureAlgorithm.getName());
    }

    public static X509Certificate generateSelfSignedCertificate(X500Name issuerName, X500Name subjectName, PublicKey publicKey, PrivateKey privateKey, AlgorithmEnum signatureAlgorithm) throws OperatorCreationException, CertificateException {
        return generateSelfSignedCertificate(issuerName, subjectName, publicKey, privateKey, signatureAlgorithm.getName());
    }

    public static String generateSelfSignedCertificatePem(X500Name issuerName, X500Name subjectName, PublicKey publicKey, PrivateKey privateKey, AlgorithmEnum signatureAlgorithm) throws CertificateException, OperatorCreationException {
        return PEMUtil.formatCRTPem(generateSelfSignedCertificate(issuerName, subjectName, publicKey, privateKey, signatureAlgorithm).getEncoded());
    }

    public static String generateSelfSignedCertificatePem(X500NameInfo issuerNameInfo, X500NameInfo subjectNameInfo, PublicKey publicKey, PrivateKey privateKey, AlgorithmEnum signatureAlgorithm) throws CertificateException, OperatorCreationException {
        return PEMUtil.formatCRTPem(generateSelfSignedCertificate(issuerNameInfo.build(), subjectNameInfo.build(), publicKey, privateKey, signatureAlgorithm).getEncoded());
    }

    public static String generateSelfSignedCertificatePem(X500Name issuerName, X500Name subjectName, PublicKey publicKey, PrivateKey privateKey, String signatureAlgorithm) throws CertificateException, OperatorCreationException {
        return PEMUtil.formatCRTPem(generateSelfSignedCertificate(issuerName, subjectName, publicKey, privateKey, signatureAlgorithm).getEncoded());
    }

    public static String generateSelfSignedCertificatePem(X500NameInfo issuerNameInfo, X500NameInfo subjectNameInfo, PublicKey publicKey, PrivateKey privateKey, String signatureAlgorithm) throws CertificateException, OperatorCreationException {
        return PEMUtil.formatCRTPem(generateSelfSignedCertificate(issuerNameInfo.build(), subjectNameInfo.build(), publicKey, privateKey, signatureAlgorithm).getEncoded());
    }


    public static X509Certificate analysisX509Certificate(InputStream inputStream) throws CertificateException, NoSuchProviderException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509",  new BouncyCastleProvider());
        return (X509Certificate) certificateFactory.generateCertificate(inputStream);
    }

    public static X509Certificate analysisX509Certificate(File file) throws CertificateException, IOException, NoSuchProviderException {
        try (FileInputStream inputStream = new FileInputStream(file)) {
            return analysisX509Certificate(inputStream);
        }
    }

    public static X509Certificate analysisX509Certificate(String pem) throws CertificateException, IOException, NoSuchProviderException {
        try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(Base64.decode(pem.replaceAll(".*BEGIN.*?.*|.*END.*?.*", "")))) {
            return analysisX509Certificate(byteArrayInputStream);
        }
    }

    public static X509Certificate analysisX509Certificate(byte[] encoded) throws CertificateException, IOException, NoSuchProviderException {
        try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(encoded)) {
            return analysisX509Certificate(byteArrayInputStream);
        }
    }
}
