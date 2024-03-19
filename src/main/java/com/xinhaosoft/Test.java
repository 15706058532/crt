package com.xinhaosoft;

import cn.hutool.http.HttpUtil;
import com.xinhaosoft.cert.CERTUtil;
import org.apache.commons.codec.binary.Base16;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CRLReason;
import java.security.cert.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;

public class Test {
    /**
     * @param args
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchProviderException
     * @throws CRLException
     */
    public static void main(String[] args) throws CertificateException, IOException, NoSuchProviderException, CRLException {
        //-----证书解析 -----
        X509Certificate rsaX509Certificate1 = CERTUtil.analysisX509Certificate(new FileInputStream(new File("D:\\新建文件夹\\xinhao.com.der")));
        //获取CRL吊销证书请求地址
        byte[] crlExtensionValue = rsaX509Certificate1.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (crlExtensionValue != null) {
            getCrlUrl(crlExtensionValue);
        }
        //获取OCSP请求地址
        byte[] ocspExtensionValue = rsaX509Certificate1.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (ocspExtensionValue != null) {
            getOcspUrl(ocspExtensionValue);
        }


    }

    /**
     * 获取OCSP请求地址
     *
     * @param ocspExtensionValue 扩展值
     */
    private static void getOcspUrl(byte[] ocspExtensionValue) {
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

    /**
     * 获取CRL吊销证书请求地址
     *
     * @param crlExtensionValue
     * @throws CertificateException
     * @throws NoSuchProviderException
     * @throws CRLException
     */
    private static void getCrlUrl(byte[] crlExtensionValue) throws CertificateException, NoSuchProviderException, CRLException {
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
                            crlAnalysis(uri.getString());
                        }
                    }
                }
            }
        }
        System.out.println("CRL 地址：" + urls);
    }

    /**
     * 解析吊销证书列表
     *
     * @param url
     * @throws CertificateException
     * @throws NoSuchProviderException
     * @throws CRLException
     */
    private static void crlAnalysis(String url) throws CertificateException, NoSuchProviderException, CRLException {
        Security.addProvider(new BouncyCastleProvider());
        byte[] bytes = HttpUtil.downloadBytes(url);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
        X509CRL crl = (X509CRL) certFactory.generateCRL(new ByteArrayInputStream(bytes));

        System.out.println("发行者: " + crl.getIssuerDN());
        System.out.println("本次更新时间: " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(crl.getThisUpdate()));
        System.out.println("下次更新时间: " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(crl.getNextUpdate()));
        System.out.println("签名算法名称: " + crl.getSigAlgName());
        System.out.println("签名值: " + new Base16().encodeAsString(crl.getSignature()));

        for (X509CRLEntry x509CRLEntry : crl.getRevokedCertificates()) {
            System.out.println("----------------------------------------");
            System.out.println("证书序列号: " + x509CRLEntry.getSerialNumber());
            System.out.println("吊销日期: " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(x509CRLEntry.getRevocationDate()));
            CRLReason revocationReason = x509CRLEntry.getRevocationReason();
            String reasonText;
            if (revocationReason != null) {
                switch (revocationReason) {
                    case UNUSED:
                        reasonText = "未使用";
                        break;
                    case SUPERSEDED:
                        reasonText = "证书替换";
                        break;
                    case AA_COMPROMISE:
                        reasonText = "属性认证机构（AA）泄密";
                        break;
                    case CA_COMPROMISE:
                        reasonText = "认证中心（CA）泄密";
                        break;
                    case KEY_COMPROMISE:
                        reasonText = "密钥损坏";
                        break;
                    case REMOVE_FROM_CRL:
                        reasonText = "从CRL中移除，重新变为有效";
                        break;
                    case CERTIFICATE_HOLD:
                        reasonText = "证书暂停使用";
                        break;
                    case AFFILIATION_CHANGED:
                        reasonText = "关联信息变更";
                        break;
                    case PRIVILEGE_WITHDRAWN:
                        reasonText = "撤销权限";
                        break;
                    case CESSATION_OF_OPERATION:
                        reasonText = "停止运营";
                        break;
                    case UNSPECIFIED:
                    default:
                        reasonText = "未指定";
                }
            } else {
                reasonText = "未指定";
            }
            System.out.println("撤销原因: " + reasonText);
            // 其他信息
        }
    }
}
