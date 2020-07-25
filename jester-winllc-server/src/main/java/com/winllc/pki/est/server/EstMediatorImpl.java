package com.winllc.pki.est.server;

import com.winllc.acme.common.model.acme.Identifier;
import com.winllc.acme.common.util.CertUtil;
import com.winllc.ra.client.CertAuthorityConnection;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.jester.CertificationRequest;
import org.jscep.jester.EstMediator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

@Component
public class EstMediatorImpl implements EstMediator {

    @Autowired
    private CertAuthorityConnection certAuthorityConnection;

    @Override
    public X509Certificate[] getCaCertificates() {
        try {
            Certificate[] trustChain = certAuthorityConnection.getTrustChain();
            return (X509Certificate[]) trustChain;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return new X509Certificate[0];
    }

    @Override
    public String[] getCsrAttributes() {
        //todo
        return new String[0];
    }

    @Override
    public X509Certificate enroll(CertificationRequest csr) {
        //todo connection to WIN RA to apply controls

       return enroll(csr, null);
    }

    @Override
    public X509Certificate enroll(CertificationRequest csr, String accountId) {
        Set<Identifier> identifierSet = new HashSet<>();
        Identifier identifier = new Identifier();
        identifier.setType("dns");
        identifier.setValue("est.winllc-dev.com");
        identifierSet.add(identifier);

        try {
            PKCS10CertificationRequest pkcs10CertificationRequest = new PKCS10CertificationRequest(csr.getBytes());

            X509Certificate certificate = certAuthorityConnection.issueCertificate(identifierSet, accountId, pkcs10CertificationRequest);

            System.out.println("Issued cert");
            System.out.println(CertUtil.toPEM(certificate));

            return certificate;
        }catch (Exception e){
            e.printStackTrace();
        }

        return null;
    }
}
