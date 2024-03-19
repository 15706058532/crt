package com.xinhaosoft;

import info.clearthought.layout.TableLayout;

import javax.swing.*;
import java.awt.*;
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.Iterator;
import java.util.Set;

public class MainFrame extends JFrame {
    private static final long serialVersionUID = 248372793120987959L;

    public MainFrame() throws HeadlessException {
        super("超级工具");
        setSize(1250, 900);
        setLocationRelativeTo(null);
        setVisible(true);
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        init();

    }

    private void init() {
        setLayout(new TableLayout(new double[][]{{8, TableLayout.FILL, 8}, {8, 50, TableLayout.FILL, 8}}));

        JPanel labelPanel = new JPanel();
        labelPanel.setBorder(BorderFactory.createMatteBorder(1, 1, 0, 1, Color.GRAY));
        add(labelPanel, "1,1,1,1");
        labelPanel.setLayout(new TableLayout(new double[][]{{80, 80, 80}, {TableLayout.FILL}}));
        JLabel rsaLabel = new JLabel("RSA");
        JLabel sm2Label = new JLabel("SM2");
        JLabel crtLabel = new JLabel("证书");
        JLabel jksLabel = new JLabel("JKS");


        JPanel contentPanel = new JPanel();
        contentPanel.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 1, Color.GRAY));
        add(contentPanel, "1,2,1,2");

        paintAll(getGraphics());
    }

    public static void main(String[] args) {
        try {
            // 读取CRL文件
            FileInputStream crlFileInputStream = new FileInputStream("C:\\Users\\pc\\Desktop\\gsrsaovsslca2018.crl");

            // 创建X.509证书工厂
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

            // 解析CRL
            X509CRL crl = (X509CRL) certificateFactory.generateCRL(crlFileInputStream);

            // 获取吊销证书列表
            Set<? extends X509CRLEntry> revokedCertificates = crl.getRevokedCertificates();

            if (revokedCertificates != null) {
                // 遍历吊销证书列表
                Iterator<? extends X509CRLEntry> iterator = revokedCertificates.iterator();
                while (iterator.hasNext()) {
                    X509CRLEntry entry = iterator.next();
                    System.out.println("Serial Number: " + entry.getSerialNumber());
                    System.out.println("吊销 Date: " + entry.getRevocationDate());
                    System.out.println("吊销理由：" + (entry.getRevocationReason() != null ? entry.getRevocationReason().name() : ""));
                    System.out.println();
                    // 可以进一步处理和检查吊销证书的其他信息
                    // ...
                }
            } else {
                System.out.println("No revoked certificates found.");
            }

            crlFileInputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
