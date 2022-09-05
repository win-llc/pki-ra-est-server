package com.winllc.ra.est;

import com.winllc.acme.common.client.ApiClient;
import com.winllc.acme.common.client.api.CertAuthorityConnectionServiceApi;
import com.winllc.acme.common.client.api.EstServerManagementServiceApi;
import com.winllc.acme.common.client.model.EstServerProperties;
import com.winllc.acme.common.client.model.RACertificateIssueRequest;
import com.winllc.acme.common.model.acme.Identifier;
import com.winllc.acme.common.util.CertUtil;
import com.winllc.ra.est.protocol.CertificationRequest;
import com.winllc.ra.est.protocol.EstMediator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class EstMediatorImpl implements EstMediator {

    private static final Logger log = LogManager.getLogger(EstMediatorImpl.class);

    private final ApiClient apiClient;

    @Value("${win-ra.properties-config-name}")
    private String propertiesConfigName;

    public EstMediatorImpl(ApiClient apiClient) {
        this.apiClient = apiClient;
    }

    @Override
    public X509Certificate[] getCaCertificates() {
        try {
            EstServerManagementServiceApi estServerManagementServiceApi = new EstServerManagementServiceApi(apiClient);
            EstServerProperties serverProperties = estServerManagementServiceApi.getProperties("default");

            CertAuthorityConnectionServiceApi connectionServiceApi = new CertAuthorityConnectionServiceApi(apiClient);
            String trustChainResponse = connectionServiceApi.getTrustChain(serverProperties.getCaConnectionName());
            Certificate[] trustChain = CertUtil.trustChainStringToCertArray(trustChainResponse);
            List<X509Certificate> certs = Stream.of(trustChain)
                    .map(c -> CertUtil.toPEM(c))
                    .map(p -> {
                        try {
                            return CertUtil.base64ToCert(p);
                        } catch (CertificateException | IOException e) {
                            log.error("Could not process cert", e);
                        }
                        return null;
                    })
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());
            return certs.toArray(new X509Certificate[0]);
        } catch (Exception e) {
            log.error("Could not get CA Certs", e);
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

            Optional<RDN> cnOptional = Stream.of(pkcs10CertificationRequest.getSubject().getRDNs())
                    .filter(rdn -> rdn.getFirst().getType().getId().equals("2.5.4.3"))
                    .findFirst();

            RDN cn = cnOptional.get();
            AttributeTypeAndValue first = cn.getFirst();

            Set<Identifier> identifierSet = new HashSet<>();
            Identifier identifier = new Identifier();
            identifier.setType("dns");
            identifier.setValue(first.getValue().toString());
            identifierSet.add(identifier);

            String dnsNames = identifierSet.stream().map(Identifier::getValue).collect(Collectors.joining(","));
            CertAuthorityConnectionServiceApi connectionServiceApi = new CertAuthorityConnectionServiceApi(apiClient);

            EstServerManagementServiceApi estServerManagementServiceApi = new EstServerManagementServiceApi(apiClient);
            EstServerProperties properties = estServerManagementServiceApi.getProperties(propertiesConfigName);

            RACertificateIssueRequest raCertificateRequest = new RACertificateIssueRequest();
            raCertificateRequest.accountKid(accountId);
            raCertificateRequest.certAuthorityName(properties.getCaConnectionName());
            raCertificateRequest.dnsNames(dnsNames);
            raCertificateRequest.csr(CertUtil.certificationRequestToPEM(pkcs10CertificationRequest));

            String base64Cert = connectionServiceApi.issueCertificate(raCertificateRequest);
            X509Certificate certificate = CertUtil.base64ToCert(base64Cert);

            System.out.println("Issued cert");
            System.out.println(CertUtil.toPEM(certificate));

            return certificate;
        }catch (Exception e){
            log.error("Could not process", e);
        }

        return null;
    }
}
