package com.xinhaosoft.cert;

import lombok.Data;
import lombok.experimental.Accessors;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

/**
 * 证书主题
 */
@Data
@Accessors(chain = true)
public class X500NameInfo {
    /**
     * 国家
     */
    private String C;
    /**
     * 省或市
     */
    private String ST;
    /**
     * 区或县
     */
    private String L;
    /**
     * 公司或组织名称
     */
    private String O;
    /**
     * 部门名称
     */
    private String OU;
    /**
     * 名称（一般填写域名）
     */
    private String CN;
    /**
     * 邮箱
     */
    private String E;

    public X500NameInfo(String C, String ST, String L, String O, String OU, String CN, String E) {
        this.C = C;
        this.ST = ST;
        this.L = L;
        this.O = O;
        this.OU = OU;
        this.CN = CN;
        this.E = E;
    }

    public X500Name build() {
        X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        if (StringUtils.isNotBlank(C)) {
            x500NameBuilder.addRDN(BCStyle.C, C);
        } else {
            x500NameBuilder.addRDN(BCStyle.C, "CN");
        }
        if (StringUtils.isNotBlank(ST)) {
            x500NameBuilder.addRDN(BCStyle.ST, ST);
        }
        if (StringUtils.isNotBlank(L)) {
            x500NameBuilder.addRDN(BCStyle.L, L);
        }
        if (StringUtils.isNotBlank(O)) {
            x500NameBuilder.addRDN(BCStyle.O, O);
        }
        if (StringUtils.isNotBlank(OU)) {
            x500NameBuilder.addRDN(BCStyle.OU, OU);
        }
        if (StringUtils.isNotBlank(CN)) {
            x500NameBuilder.addRDN(BCStyle.CN, CN);
        }
        if (StringUtils.isNotBlank(E)) {

            x500NameBuilder.addRDN(BCStyle.E, E);
        }
        return x500NameBuilder.build();
    }
}
