package com.xinhaosoft.p12;

import com.xinhaosoft.pfx.PFXUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.stream.Collectors;

public class P12Util {

    public static void generateP12(OutputStream outputStream, String alias, String keystorePassword, List<Certificate> certificates, String certPassword, PrivateKey privateKey) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, NoSuchProviderException {
        PFXUtil.generatePFX(outputStream, alias, keystorePassword, certificates, certPassword, privateKey);
    }

    public static void generateP12(String keystorePath, String alias, String keystorePassword, List<Certificate> certificates, String certPassword, PrivateKey privateKey) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, NoSuchProviderException {
        try (FileOutputStream outputStream = new FileOutputStream(keystorePath);) {
            generateP12(outputStream, alias, keystorePassword, certificates, certPassword, privateKey);
        }
    }

    public static void generateP12(File keystoreFile, String alias, String keystorePassword, List<Certificate> certificates, String certPassword, PrivateKey privateKey) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, NoSuchProviderException {
        generateP12(keystoreFile.getPath(), alias, keystorePassword, certificates, certPassword, privateKey);
    }

    public static List<X509Certificate> analysisP12(InputStream inputStream, String keystorePassword) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        List<Certificate> certificates = new ArrayList<>();
        KeyStore keyStore = KeyStore.getInstance("PKCS12",new BouncyCastleProvider());
        keyStore.load(inputStream, keystorePassword.toCharArray());
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String element = aliases.nextElement();
            Certificate[] certificateChain = keyStore.getCertificateChain(element);
            if (certificateChain != null) {
                certificates.addAll(Arrays.asList(certificateChain));
            } else {
                certificates.add(keyStore.getCertificate(element));
            }
        }
        return certificates.stream().map(certificate -> (X509Certificate) certificate).collect(Collectors.toList());
    }

    public static List<X509Certificate> analysisP12(String keystorePath, String keystorePassword) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        try (FileInputStream fileInputStream = new FileInputStream(keystorePath)) {
            return analysisP12(fileInputStream, keystorePassword);
        }
    }

    public static List<X509Certificate> analysisP12(File keystoreFile, String keystorePassword) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        return analysisP12(keystoreFile.getPath(), keystorePassword);
    }


}
