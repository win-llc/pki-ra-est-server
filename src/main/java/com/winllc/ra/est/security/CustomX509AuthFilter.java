package com.winllc.ra.est.security;


import com.winllc.acme.common.client.ApiClient;
import com.winllc.acme.common.client.ApiException;
import com.winllc.acme.common.client.api.ValidationServiceApi;
import com.winllc.acme.common.client.model.CertificateValidationForm;
import com.winllc.acme.common.client.model.RAAccountValidationResponse;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

public class CustomX509AuthFilter extends X509AuthenticationFilter {

    private final ApiClient apiClient;

    public CustomX509AuthFilter(ApiClient apiClient) {
        super();
        this.apiClient = apiClient;
    }

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        X509Certificate certificate = extractClientCertificate(request);

        if(certificate != null) {
            System.out.println("Extracted certificate: "+certificate.getSubjectDN().getName());

            //if(!isRevoked(certificate)) {
                X509AuthenticationToken token
                        = new X509AuthenticationToken(certificate.getSubjectDN().getName().replace(", ", ","), certificate);

                return token;
                /*
            }else{
                System.out.println("Could not authenticate, cert revoked: "+certificate.getSubjectDN().getName());
            }

                 */
        }

        return null;
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        X509Certificate certificate = this.extractClientCertificate(request);
        X509AuthenticationToken token
                = new X509AuthenticationToken(certificate.getSubjectDN().getName().replace(", ", ","), certificate);



        return token;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            Authentication authResult) throws IOException, ServletException {
        X509Certificate certificate = extractClientCertificate(request);

        System.out.println("Auth success for: "+certificate.getSubjectDN().getName());

        if(authResult.getCredentials() instanceof  X509AuthenticationToken) {
            X509AuthenticationToken token = (X509AuthenticationToken) authResult.getCredentials();

            CertificateValidationForm form = new CertificateValidationForm();
            form.setSerial(certificate.getSerialNumber().toString());
            form.setIssuerDn(certificate.getIssuerDN().getName());

            boolean valid = false;
            ValidationServiceApi validationServiceApi = new ValidationServiceApi(apiClient);
            try {
                RAAccountValidationResponse raResponse = validationServiceApi.validateServerReEnrollment(form);
                valid = raResponse.isValid();
                token.setAccountId(raResponse.getAccountId());
            } catch (ApiException e) {
                e.printStackTrace();
            }

            if(valid) {
                super.successfulAuthentication(request, response, authResult);
            }else{
                super.unsuccessfulAuthentication(request, response, new DisabledException("Could not find account for server"));
            }
        }else{
            super.successfulAuthentication(request, response, authResult);
        }
    }



    private X509Certificate extractClientCertificate(HttpServletRequest request) {
        X509Certificate[] certs = (X509Certificate[]) request
                .getAttribute("javax.servlet.request.X509Certificate");

        if (certs != null && certs.length > 0) {
            if (logger.isDebugEnabled()) {
                logger.debug("X.509 client authentication certificate:" + certs[0]);
            }

            return certs[0];
        }

        if (logger.isDebugEnabled()) {
            logger.debug("No client certificate found in request.");
        }

        return null;
    }

    /**
     * Check to see if there is a CRL
     *
     * @return boolean
     */
    protected boolean checkForCRL(X509Certificate certificate) {
        //Log.debug("In AuthenticationFilter method checkForCRL()");
        boolean crlExists = false;

        String issuerDN = certificate.getIssuerDN().getName().replaceAll(", ", ",");

        X509CRL crl = null;//CRLStore.getInstance().getCRLByName(issuerDN);

        if (crl != null)
            crlExists = true;

        return crlExists;
    }

    /**
     * Checks to see if the certificate is revoked
     *
     * @return boolean
     */
    protected boolean isRevoked(X509Certificate certificate) {
        //Log.debug("In AuthenticationFilter method isRevoked()");
        boolean revoked = false;

        String issuerDN = certificate.getIssuerDN().getName();

        issuerDN = issuerDN.replaceAll(", ", ",");

        X509CRL crl = null;//CRLStore.getInstance().getCRLByName(issuerDN);

        if (crl != null) {
            if (crl.isRevoked(certificate)) {
                revoked = true;
            }
        }
        return revoked;
    }
}