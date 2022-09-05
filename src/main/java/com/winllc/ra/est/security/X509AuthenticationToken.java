package com.winllc.ra.est.security;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.security.cert.X509Certificate;

public class X509AuthenticationToken extends UsernamePasswordAuthenticationToken {

    private final X509Certificate certificate;
    private String accountId;

    public X509AuthenticationToken(Object principal, X509Certificate certificate) {
        super(principal, "");
        this.certificate = certificate;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public String getAccountId() {
        return accountId;
    }

    public void setAccountId(String accountId) {
        this.accountId = accountId;
    }
}