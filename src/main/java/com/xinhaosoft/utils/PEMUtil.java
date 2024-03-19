package com.xinhaosoft.utils;

import cn.hutool.crypto.PemUtil;


public class PEMUtil {

    public static String formatCSRPem(byte[] encoded) {
        return PemUtil.toPem("CERTIFICATE REQUEST", encoded);
    }

    public static String formatCRTPem(byte[] encoded) {
        return PemUtil.toPem("CERTIFICATE", encoded);
    }

    public static String formatPublicKeyPem(byte[] encoded) {
        return PemUtil.toPem("PUBLIC KEY", encoded);
    }

    public static String formatPrivateKeyPem(byte[] encoded) {
        return PemUtil.toPem("PRIVATE KEY", encoded);
    }

    public static void main(String[] args) {
    }
}
