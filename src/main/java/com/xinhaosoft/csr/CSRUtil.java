package com.xinhaosoft.csr;

import com.xinhaosoft.cert.X500NameInfo;
import com.xinhaosoft.enums.AlgorithmEnum;
import com.xinhaosoft.utils.PEMUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.PublicKey;

@Slf4j
public class CSRUtil {
    public static String generateCSR(X500Name subjectName, PublicKey publicKey, PrivateKey privateKey, String algorithmName) throws OperatorCreationException, IOException {
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
        // 创建 ContentSigner 对象
        ContentSigner contentSigner = new JcaContentSignerBuilder(algorithmName).setProvider(new BouncyCastleProvider()).build(privateKey);
        // 创建证书请求构建器
        JcaPKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(subjectName, publicKey);
        // 构建证书请求对象
        PKCS10CertificationRequest csr = requestBuilder.build(contentSigner);
        return PEMUtil.formatCSRPem(csr.getEncoded());

    }

    public static String generateCSR(X500NameInfo subjectNameInfo, PublicKey publicKey, PrivateKey privateKey, String algorithmName) throws OperatorCreationException, IOException {
        return generateCSR(subjectNameInfo.build(), publicKey, privateKey, algorithmName);
    }

    public static String generateCSR(X500Name subjectName, PublicKey publicKey, PrivateKey privateKey, AlgorithmEnum algorithmEnum) throws OperatorCreationException, IOException {
        return generateCSR(subjectName, publicKey, privateKey, algorithmEnum.getName());
    }

    public static String generateCSR(X500NameInfo subjectNameInfo, PublicKey publicKey, PrivateKey privateKey, AlgorithmEnum algorithmEnum) throws OperatorCreationException, IOException {
        return generateCSR(subjectNameInfo.build(), publicKey, privateKey, algorithmEnum.getName());
    }

    public static PKCS10CertificationRequest analysisCSR(InputStream inputStream) throws IOException {
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(inputStream))) {
            return (PKCS10CertificationRequest) pemParser.readObject();
        }
    }

    public static PKCS10CertificationRequest analysisCSR(File file) throws IOException {
        try (InputStream inputStream = Files.newInputStream(file.toPath())) {
            return analysisCSR(inputStream);
        }
    }

    public static PKCS10CertificationRequest analysisCSR(String pem) throws IOException {
        try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8))) {
            return analysisCSR(byteArrayInputStream);
        }

    }

    public static PKCS10CertificationRequest analysisCSR(byte[] encoded) throws IOException {
        return analysisCSR(PEMUtil.formatCSRPem(encoded));
    }

    //TODO 这里还有一个问题没处理，私钥在加密激里，加密机可以做签名，但java生成请求证书时必须有私钥，加密机的签名，如何整合进java已经生成的请求文件内

}
