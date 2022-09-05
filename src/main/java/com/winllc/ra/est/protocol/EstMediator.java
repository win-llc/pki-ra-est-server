package com.winllc.ra.est.protocol;

import java.security.cert.X509Certificate;

public interface EstMediator {
    X509Certificate[] getCaCertificates();
    String[] getCsrAttributes();
    X509Certificate enroll(CertificationRequest csr);
    X509Certificate enroll(CertificationRequest csr, String accountId);
}
