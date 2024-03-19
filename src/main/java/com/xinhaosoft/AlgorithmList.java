//package com.xinhaosoft;
//
//import com.xinhaosoft.cert.CertUtil;
//import com.xinhaosoft.enums.AlgorithmEnum;
//import com.xinhaosoft.rsa.RSAUtil;
//import com.xinhaosoft.sm2.SM2Util;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//
//import java.security.*;
//import java.security.cert.X509Certificate;
//import java.util.HashSet;
//import java.util.Set;
//
//public class AlgorithmList {
//    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
//        Security.addProvider(new BouncyCastleProvider());
//        KeyPair keyPair = RSAUtil.generateRsaKey(2048);
//        KeyPair sm2KeyPair = SM2Util.generateRsaKey();
//        Provider[] providers = Security.getProviders();
//        Set<String> name = new HashSet<>();
//        // 遍历所有提供者
//        for (Provider provider : providers) {
//            // 获取该提供者支持的算法服务
//            for (Provider.Service service : provider.getServices()) {
//                // 判断算法是否为RSA
//                if (service.getType().equals("Signature")) {
//                    // 输出算法名称
//                    try {
//                        X509Certificate x509Certificate = CertUtil.generateSelfSignedCertificate(keyPair.getPublic(), keyPair.getPrivate(), service.getAlgorithm());
////                        System.out.println(service.getAlgorithm());
//                        name.add(service.getAlgorithm());
//                    } catch (Exception ignored) {
//
//                    }
//                }
//            }
//        }
//        for (String n : name) {
//            System.out.println("    /**\n" +
//                    "     * "+n+"\n" +
//                    "     */\n" +
//                    "    "+n.replaceAll("-","_").replaceAll("\\(","_").replaceAll("\\)","_")+"(\""+n+"\"),");
//        }
//         keyPair = SM2Util.generateRsaKey();
//        providers = Security.getProviders();
//        Set<String> names = new HashSet<>(new HashSet<>(name));
//         name = new HashSet<>();
//        // 遍历所有提供者
//        for (Provider provider : providers) {
//            // 获取该提供者支持的算法服务
//            for (Provider.Service service : provider.getServices()) {
//                // 判断算法是否为RSA
////                if (service.getType().equals("Signature")) {
//                    // 输出算法名称
//                    try {
//                        X509Certificate x509Certificate = CertUtil.generateSelfSignedCertificate(keyPair.getPublic(), keyPair.getPrivate(), service.getAlgorithm());
////                        System.out.println(service.getAlgorithm());
//                        name.add(service.getAlgorithm());
//                    } catch (Exception ignored) {
//
//                    }
////                }
//            }
//        }
//        for (String n : name) {
//            System.out.println("    /**\n" +
//                    "     * "+n+"\n" +
//                    "     */\n" +
//                    "    "+n.replaceAll("-","_").replaceAll("\\(","_").replaceAll("\\)","_")+"(\""+n+"\"),");
//        }
//        names.addAll(new HashSet<>(name));
//        AlgorithmEnum[] values = AlgorithmEnum.values();
//        System.out.println();
//        System.out.println();
//        System.out.println();
//        System.out.println("-----------------------");
//        System.out.println();
//        System.out.println();
//        System.out.println();
//        System.out.println();
//        for (AlgorithmEnum value : values) {
//            if(!names.contains(value.getName())){
//                System.out.println(value);
//            }
//        }
//
//    }
//}
