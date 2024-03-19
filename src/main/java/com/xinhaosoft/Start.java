package com.xinhaosoft;

import cn.hutool.core.io.FileUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.asymmetric.SM2;
import com.google.common.io.BaseEncoding;
import com.xinhaosoft.cert.CERTUtil;
import com.xinhaosoft.cert.X500NameInfo;
import com.xinhaosoft.csr.CSRUtil;
import com.xinhaosoft.enums.AlgorithmEnum;
import com.xinhaosoft.jks.JKSUtil;
import com.xinhaosoft.p12.P12Util;
import com.xinhaosoft.pfx.PFXUtil;
import com.xinhaosoft.rsa.RSAUtil;
import com.xinhaosoft.sm2.SM2Util;
import com.xinhaosoft.utils.PEMUtil;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class Start {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, CertificateException, OperatorCreationException, IOException, KeyStoreException, InvalidAlgorithmParameterException, InvalidKeySpecException, InvalidKeyException, SignatureException, CertStoreException {
        Security.addProvider(new BouncyCastleProvider());
/*
        X500NameInfo issuerNameInfo = new X500NameInfo("CN", "陕西", "西安", "xinhao", "yanfa", "xinhao.com", "xinhao.com");
        X500NameInfo subjectNameInfo = new X500NameInfo("CN", "陕西", "西安", "xinhao", "yanfa", "xinhao.com", "xinhao.com");


        KeyPair rsaKeyPair = RSAUtil.generateRsaKey(2048);

        //----RSA公私钥创建
        String rsaPublicKeyPem = RSAUtil.rsaPublicKeyPem(rsaKeyPair.getPublic());
        String rsaPrivateKeyPem = RSAUtil.rsaPrivateKeyPem(rsaKeyPair.getPrivate());
        System.out.println(rsaPublicKeyPem);
        System.out.println(rsaPrivateKeyPem);
        FileUtil.writeString(rsaPublicKeyPem, "C:\\Users\\pc\\Desktop\\tools\\rsa.public.key.pem", StandardCharsets.UTF_8);
        FileUtil.writeString(rsaPrivateKeyPem, "C:\\Users\\pc\\Desktop\\tools\\rsa.private.key.pem", StandardCharsets.UTF_8);

        //----RSA公私钥创建

        //-----RSApem公私钥解析
        System.out.println(PEMUtil.formatPublicKeyPem(RSAUtil.analysisRSAPublicKey(new File("C:\\Users\\pc\\Desktop\\tools\\rsa.public.key.pem")).getEncoded()));
        System.out.println(PEMUtil.formatPublicKeyPem(RSAUtil.analysisRSAPublicKey(FileUtil.readString("C:\\Users\\pc\\Desktop\\tools\\rsa.public.key.pem", StandardCharsets.UTF_8)).getEncoded()));

        System.out.println(PEMUtil.formatPrivateKeyPem(RSAUtil.analysisRSAPrivateKey(new File("C:\\Users\\pc\\Desktop\\tools\\rsa.private.key.pem")).getEncoded()));
        System.out.println(PEMUtil.formatPrivateKeyPem(RSAUtil.analysisRSAPrivateKey(FileUtil.readString("C:\\Users\\pc\\Desktop\\tools\\rsa.private.key.pem", StandardCharsets.UTF_8)).getEncoded()));
        //-----RSApem公私钥解析

        KeyPair sm2KeyPair = SM2Util.generateRsaKey();
        //----SM2公私钥创建
        String sm2PublicKeyPem = SM2Util.sm2PublicKeyPem(sm2KeyPair.getPublic());
        String sm2PrivateKeyPem = SM2Util.sm2PrivateKeyPem(sm2KeyPair.getPrivate());
        System.out.println(rsaPublicKeyPem);
        System.out.println(rsaPrivateKeyPem);
        FileUtil.writeString(sm2PublicKeyPem, "C:\\Users\\pc\\Desktop\\tools\\sm2.public.key.pem", StandardCharsets.UTF_8);
        FileUtil.writeString(sm2PrivateKeyPem, "C:\\Users\\pc\\Desktop\\tools\\sm2.private.key.pem", StandardCharsets.UTF_8);
        //----SM2公私钥创建


        //-----SM2pem公私钥解析
        System.out.println(PEMUtil.formatPublicKeyPem(SM2Util.analysisSM2PublicKey(new File("C:\\Users\\pc\\Desktop\\tools\\sm2.public.key.pem")).getEncoded()));
        System.out.println(PEMUtil.formatPublicKeyPem(SM2Util.analysisSM2PublicKey(FileUtil.readString("C:\\Users\\pc\\Desktop\\tools\\sm2.public.key.pem", StandardCharsets.UTF_8)).getEncoded()));

        System.out.println(PEMUtil.formatPrivateKeyPem(SM2Util.analysisSM2PrivateKey(new File("C:\\Users\\pc\\Desktop\\tools\\sm2.private.key.pem")).getEncoded()));
        System.out.println(PEMUtil.formatPrivateKeyPem(SM2Util.analysisSM2PrivateKey(FileUtil.readString("C:\\Users\\pc\\Desktop\\tools\\sm2.private.key.pem", StandardCharsets.UTF_8)).getEncoded()));
        //-----SM2pem公私钥解析


        //----证书请求文件创建
        String csr = CSRUtil.generateCSR(subjectNameInfo, sm2KeyPair.getPublic(), sm2KeyPair.getPrivate(), AlgorithmEnum.SM3WITHSM2);
        System.out.println(csr);
        FileUtil.writeString(csr, "C:\\Users\\pc\\Desktop\\tools\\sm2.csr", StandardCharsets.UTF_8);
        String rsaCsr = CSRUtil.generateCSR(subjectNameInfo, rsaKeyPair.getPublic(), rsaKeyPair.getPrivate(), AlgorithmEnum.SHA1withRSA);
        System.out.println(rsaCsr);
        FileUtil.writeString(rsaCsr, "C:\\Users\\pc\\Desktop\\tools\\rsa.csr", StandardCharsets.UTF_8);
        //----证书请求文件创建

        //------证书请求文件的解析
        PKCS10CertificationRequest pkcs10CertificationRequest = CSRUtil.analysisCSR(new File("C:\\Users\\pc\\Desktop\\tools\\sm2.csr"));
        assert pkcs10CertificationRequest != null;
        X500Name subject = pkcs10CertificationRequest.getSubject();
        System.out.println(subject);

        byte[] encoded = pkcs10CertificationRequest.getSubjectPublicKeyInfo().getEncoded();
        PublicKey publicKey = SM2Util.analysisSM2PublicKey(encoded);
        PKCS10CertificationRequest pkcs10CertificationRequest1 = CSRUtil.analysisCSR(FileUtil.readString("C:\\Users\\pc\\Desktop\\tools\\sm2.csr", StandardCharsets.UTF_8));
        PKCS10CertificationRequest pkcs10CertificationRequest2 = CSRUtil.analysisCSR(pkcs10CertificationRequest.getEncoded());
        //------证书请求文件的解析


        //-----创建自签证书
        X509Certificate x509Certificate = CERTUtil.generateSelfSignedCertificate(issuerNameInfo, subjectNameInfo, sm2KeyPair.getPublic(), sm2KeyPair.getPrivate(), AlgorithmEnum.SM3WITHSM2);
        String sm2Crt = CERTUtil.generateSelfSignedCertificatePem(issuerNameInfo, subjectNameInfo, sm2KeyPair.getPublic(), sm2KeyPair.getPrivate(), AlgorithmEnum.SM3WITHSM2);
        System.out.println(sm2Crt);
        FileUtil.writeString(sm2Crt, "C:\\Users\\pc\\Desktop\\tools\\sm2.crt.pem", StandardCharsets.UTF_8);
        String rsaCrt = CERTUtil.generateSelfSignedCertificatePem(issuerNameInfo, subjectNameInfo, rsaKeyPair.getPublic(), rsaKeyPair.getPrivate(), AlgorithmEnum.SHA1withRSA);
        System.out.println(rsaCrt);
        FileUtil.writeString(rsaCrt, "C:\\Users\\pc\\Desktop\\tools\\rsa.crt.pem", StandardCharsets.UTF_8);
        X509Certificate rsaX509Certificate = CERTUtil.generateSelfSignedCertificate(issuerNameInfo.build(), subjectNameInfo.build(), rsaKeyPair.getPublic(), rsaKeyPair.getPrivate(), AlgorithmEnum.SHA256withRSA);
        //-----创建自签证书


        //-----证书解析 -----
        X509Certificate sm2X509Certificate = CERTUtil.analysisX509Certificate(new File("C:\\Users\\pc\\Desktop\\tools\\sm2.crt.pem"));
        assert sm2X509Certificate != null;
        PublicKey publicKey1 = sm2X509Certificate.getPublicKey();
        String name = sm2X509Certificate.getIssuerDN().getName();
        X509Certificate x509Certificate2 = CERTUtil.analysisX509Certificate(sm2X509Certificate.getEncoded());*/
        X509Certificate rsaX509Certificate2 = CERTUtil.analysisX509Certificate(FileUtil.readString(new File("D:\\新建文件夹\\baidu.com.pem"), StandardCharsets.UTF_8));
//        X509Certificate rsaX509Certificate1 = CERTUtil.analysisX509Certificate(FileUtil.readString(new File("D:\\新建文件夹\\certc0e364de2bc2e4479db47e7c10d68de4343714da-chain.pem"), StandardCharsets.UTF_8));
        X509Certificate rsaX509Certificate1 = CERTUtil.analysisX509Certificate(new FileInputStream(new File("D:\\新建文件夹\\xinhao.com.der")));
        //获取CRL吊销证书请求地址
        byte[] crlExtensionValue = rsaX509Certificate1.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (crlExtensionValue != null) {
            List<String> urls = new ArrayList<>();
            // 将ASN.1结构体转换为CRLDistPoint对象
            CRLDistPoint distPoint = CRLDistPoint.getInstance(DEROctetString.getInstance(crlExtensionValue).getOctets());
            // 获取DistributionPoint列表
            DistributionPoint[] distributionPoints = distPoint.getDistributionPoints();
            for (DistributionPoint distributionPoint : distributionPoints) {
                // 获取DistributionPoint的DistributionPointName
                DistributionPointName distributionPointName = distributionPoint.getDistributionPoint();
                if (distributionPointName != null) {
                    // 获取DistributionPointName中的GeneralNames
                    GeneralNames generalNames = GeneralNames.getInstance(distributionPointName.getName());
                    if (generalNames != null) {
                        // 获取GeneralNames中的GeneralName列表
                        GeneralName[] names = generalNames.getNames();
                        for (GeneralName generalName : names) {
                            if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                                // 如果GeneralName是URI类型，则返回其值
                                DERIA5String uri = DERIA5String.getInstance(generalName.getName());
                                urls.add(uri.getString());
                            }
                        }
                    }
                }
            }
            System.out.println("CRL 地址：" + urls);
        }
        //获取OCSP请求地址
        byte[] ocspExtensionValue = rsaX509Certificate1.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (ocspExtensionValue != null) {
            List<String> urls = new ArrayList<>();
            // 将扩展值转换为 AuthorityInformationAccess 对象
            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(DEROctetString.getInstance(ocspExtensionValue).getOctets());
            // 遍历 AuthorityInformationAccess 对象中的 GeneralName 列表
            for (AccessDescription gn : aia.getAccessDescriptions()) {
                // 检查 GeneralName 的类型是否为 OCSP
                if (gn.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
                    // 获取 OCSP 地址
                    String ocspUrl = gn.getAccessLocation().getName().toString();
                    urls.add(ocspUrl);
                }
            }
            System.out.println("OCSP 地址：" + urls);
        }






        //获取CRL吊销证书请求地址
        byte[] crlExtensionValue1 = rsaX509Certificate2.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (crlExtensionValue1 != null) {
            List<String> urls = new ArrayList<>();
            // 将ASN.1结构体转换为CRLDistPoint对象
            CRLDistPoint distPoint = CRLDistPoint.getInstance(DEROctetString.getInstance(crlExtensionValue1).getOctets());
            // 获取DistributionPoint列表
            DistributionPoint[] distributionPoints = distPoint.getDistributionPoints();
            for (DistributionPoint distributionPoint : distributionPoints) {
                // 获取DistributionPoint的DistributionPointName
                DistributionPointName distributionPointName = distributionPoint.getDistributionPoint();
                if (distributionPointName != null) {
                    // 获取DistributionPointName中的GeneralNames
                    GeneralNames generalNames = GeneralNames.getInstance(distributionPointName.getName());
                    if (generalNames != null) {
                        // 获取GeneralNames中的GeneralName列表
                        GeneralName[] names = generalNames.getNames();
                        for (GeneralName generalName : names) {
                            if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                                // 如果GeneralName是URI类型，则返回其值
                                DERIA5String uri = DERIA5String.getInstance(generalName.getName());
                                urls.add(uri.getString());
                            }
                        }
                    }
                }
            }
            System.out.println("CRL 地址：" + urls);
        }
        //获取OCSP请求地址
        byte[] ocspExtensionValue1 = rsaX509Certificate2.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (ocspExtensionValue1 != null) {
            List<String> urls = new ArrayList<>();
            // 将扩展值转换为 AuthorityInformationAccess 对象
            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(DEROctetString.getInstance(ocspExtensionValue1).getOctets());
            // 遍历 AuthorityInformationAccess 对象中的 GeneralName 列表
            for (AccessDescription gn : aia.getAccessDescriptions()) {
                // 检查 GeneralName 的类型是否为 OCSP
                if (gn.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
                    // 获取 OCSP 地址
                    String ocspUrl = gn.getAccessLocation().getName().toString();
                    urls.add(ocspUrl);
                }
            }
            System.out.println("OCSP 地址：" + urls);
        }
        //-----证书解析-----

/*
        //-----JKS创建
            JKSUtil.generateJKS("C:\\Users\\pc\\Desktop\\tools\\rsa.jks", "rsa", "12345678", Arrays.asList(rsaX509Certificate, rsaX509Certificate, rsaX509Certificate), "12345678", rsaKeyPair.getPrivate());
        //JKS不支持SM2
        JKSUtil.generateJKS("C:\\Users\\pc\\Desktop\\tools\\sm2.jks", "sm2", "12345678", Arrays.asList(rsaX509Certificate,*//*sm2X509Certificate, JKS不支持sm2p256v1椭圆算法，换成sect283r1椭圆算法就行了*//*rsaX509Certificate), "12345678", sm2KeyPair.getPrivate());
        //-----JKS创建

        //-----JKS解析
        List<X509Certificate> certificates = JKSUtil.analysisJKS("C:\\Users\\pc\\Desktop\\tools\\rsa.jks", "12345678");
        for (X509Certificate certificate : certificates) {
//            System.out.println(certificate);
            BigInteger serialNumber = certificate.getSerialNumber();
            FileUtil.writeBytes(certificate.getEncoded(), new File("C:\\Users\\pc\\Desktop\\tools\\" + serialNumber + ".cer"));
            PublicKey publicKey2 = certificate.getPublicKey();
            // 计算指纹指纹
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            byte[] sha1FingerprintBytes = sha1.digest(certificate.getEncoded());
            System.out.println("指纹SHA1:" + BaseEncoding.base16().encode(sha1FingerprintBytes));
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] sha256FingerprintBytes = sha256.digest(certificate.getEncoded());
            System.out.println("指纹SHA256:" + BaseEncoding.base16().encode(sha256FingerprintBytes));
        }
        System.out.println("-------------------");
        //-----JKS解析


        //-----PFX创建
        PFXUtil.generatePFX("C:\\Users\\pc\\Desktop\\tools\\rsa.pfx", "rsa", "12345678", Collections.singletonList(rsaX509Certificate), "12345678", rsaKeyPair.getPrivate());
        PFXUtil.generatePFX("C:\\Users\\pc\\Desktop\\tools\\sm2.pfx", "sm2", "12345678", Arrays.asList(sm2X509Certificate, rsaX509Certificate), "12345678", sm2KeyPair.getPrivate());
        //-----PFX创建

        //-----PFX解析
        List<X509Certificate> pfxCertificates = PFXUtil.analysisPFX("C:\\Users\\pc\\Desktop\\tools\\sm2.pfx", "12345678");
        for (X509Certificate certificate : pfxCertificates) {
            BigInteger serialNumber = certificate.getSerialNumber();
            FileUtil.writeBytes(certificate.getEncoded(), new File("C:\\Users\\pc\\Desktop\\tools\\" + serialNumber + ".cer"));
            PublicKey publicKey2 = certificate.getPublicKey();
            // 计算指纹指纹
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            byte[] sha1FingerprintBytes = sha1.digest(certificate.getEncoded());
            System.out.println("指纹SHA1:" + BaseEncoding.base16().encode(sha1FingerprintBytes));
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] sha256FingerprintBytes = sha256.digest(certificate.getEncoded());
            System.out.println("指纹SHA256:" + BaseEncoding.base16().encode(sha256FingerprintBytes));
        }
        System.out.println("-------------------");
        //-----PFX解析


        //-----P12创建
        P12Util.generateP12("C:\\Users\\pc\\Desktop\\tools\\rsa.p12", "rsa", "12345678", Collections.singletonList(rsaX509Certificate), "12345678", rsaKeyPair.getPrivate());
        P12Util.generateP12("C:\\Users\\pc\\Desktop\\tools\\sm2.p12", "sm2", "12345678", Arrays.asList(rsaX509Certificate, sm2X509Certificate), "12345678", sm2KeyPair.getPrivate());
        //-----P12创建

        //-----P12解析
        List<X509Certificate> p12Certificates = P12Util.analysisP12("C:\\Users\\pc\\Desktop\\tools\\sm2.p12", "12345678");
        for (X509Certificate certificate : p12Certificates) {
            BigInteger serialNumber = certificate.getSerialNumber();
            FileUtil.writeBytes(certificate.getEncoded(), new File("C:\\Users\\pc\\Desktop\\tools\\" + serialNumber + ".cer"));
            PublicKey publicKey2 = certificate.getPublicKey();
            // 计算指纹指纹
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            byte[] sha1FingerprintBytes = sha1.digest(certificate.getEncoded());
            System.out.println("指纹SHA1:" + BaseEncoding.base16().encode(sha1FingerprintBytes));
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] sha256FingerprintBytes = sha256.digest(certificate.getEncoded());
            System.out.println("指纹SHA256:" + BaseEncoding.base16().encode(sha256FingerprintBytes));
        }
        System.out.println("-------------------");
        //-----P12解析


        String data = "123456";
        //SM2加解密
        System.out.println("原文：" + data);
        SM2 sm2 = new SM2(sm2KeyPair.getPrivate(), sm2KeyPair.getPublic());
        byte[] encrypt = sm2.encrypt(data.getBytes(StandardCharsets.UTF_8));
        byte[] decrypt = sm2.decrypt(encrypt);
        System.out.println("SM2解密后：" + new String(decrypt, StandardCharsets.UTF_8));
        //SM2签名验签
        byte[] sign = sm2.sign(data.getBytes(StandardCharsets.UTF_8));
        boolean verify = sm2.verify(data.getBytes(StandardCharsets.UTF_8), sign);
        System.out.println("SM2验签结果" + verify);

        //RSA加解密
        RSA rsa = new RSA(rsaKeyPair.getPrivate(), rsaKeyPair.getPublic());
        encrypt = rsa.encrypt(data.getBytes(StandardCharsets.UTF_8), KeyType.PublicKey);
        decrypt = rsa.decrypt(encrypt, KeyType.PrivateKey);
        ;
        System.out.println("RSA解密后：" + new String(decrypt, StandardCharsets.UTF_8));
        //RSA签名验签
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initSign(rsaKeyPair.getPrivate());
        // 更新要签名的数据
        signature.update(data.getBytes(StandardCharsets.UTF_8));
        // 进行签名
        sign = signature.sign();
        // 验证签名
        signature.initVerify(rsaKeyPair.getPublic());
        signature.update(data.getBytes(StandardCharsets.UTF_8));
        verify = signature.verify(sign);
        System.out.println("RSA验签结果" + verify);*/

    }
}
