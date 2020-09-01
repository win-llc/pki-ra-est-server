package com.winllc.pki.est.server;

import com.winllc.acme.common.model.acme.Identifier;
import com.winllc.acme.common.util.CertUtil;
import com.winllc.ra.client.ApiClient;
import com.winllc.ra.client.api.CertAuthorityConnectionServiceApi;
import com.winllc.ra.client.model.RACertificateIssueRequest;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.jester.CertificationRequest;
import org.jscep.jester.EstMediator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class EstMediatorImpl implements EstMediator {

    @Autowired
    private ApiClient apiClient;

    @Override
    public X509Certificate[] getCaCertificates() {
        try {
            CertAuthorityConnectionServiceApi connectionServiceApi = new CertAuthorityConnectionServiceApi(apiClient);
            String trustChainResponse = connectionServiceApi.getTrustChain("dogtag");
            Certificate[] trustChain = CertUtil.trustChainStringToCertArray(trustChainResponse);
            List<X509Certificate> certs = Stream.of(trustChain)
                    .map(c -> CertUtil.toPEM(c))
                    .map(p -> {
                        try {
                            return CertUtil.base64ToCert(p);
                        } catch (CertificateException e) {
                            e.printStackTrace();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                        return null;
                    })
                    .filter(c -> c != null)
                    .collect(Collectors.toList());
            return certs.toArray(new X509Certificate[0]);
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

        try {
            PKCS10CertificationRequest pkcs10CertificationRequest = new PKCS10CertificationRequest(csr.getBytes());

            RDN cn = pkcs10CertificationRequest.getSubject().getRDNs()[0];
            AttributeTypeAndValue first = cn.getFirst();

            Set<Identifier> identifierSet = new HashSet<>();
            Identifier identifier = new Identifier();
            identifier.setType("dns");
            identifier.setValue(first.getValue().toString());
            identifierSet.add(identifier);

            String dnsNames = identifierSet.stream().map(Identifier::getValue).collect(Collectors.joining(","));
            CertAuthorityConnectionServiceApi connectionServiceApi = new CertAuthorityConnectionServiceApi(apiClient);
            RACertificateIssueRequest raCertificateRequest = new RACertificateIssueRequest();
            raCertificateRequest.accountKid(accountId);
            raCertificateRequest.certAuthorityName("dogtag");
            raCertificateRequest.dnsNames(dnsNames);
            raCertificateRequest.csr(CertUtil.certificationRequestToPEM(pkcs10CertificationRequest));

            String base64Cert = connectionServiceApi.issueCertificate(raCertificateRequest);
            X509Certificate certificate = CertUtil.base64ToCert(base64Cert);

            System.out.println("Issued cert");
            System.out.println(CertUtil.toPEM(certificate));

            return certificate;
        }catch (Exception e){
            e.printStackTrace();
        }

        return null;
    }
}
