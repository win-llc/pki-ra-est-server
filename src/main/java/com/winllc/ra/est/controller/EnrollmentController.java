package com.winllc.ra.est.controller;

import com.winllc.ra.est.EstMediatorImpl;
import com.winllc.ra.est.io.BouncyCastleSignedDataEncoder;
import com.winllc.ra.est.io.EntityDecoder;
import com.winllc.ra.est.io.EntityEncoder;
import com.winllc.ra.est.protocol.CertificationRequest;
import com.winllc.ra.est.security.X509AuthenticationToken;
import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.codec.binary.Base64OutputStream;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.cert.X509Certificate;

import static com.winllc.ra.est.Constants.APPLICATION_PKCS7_MIME;


@Controller
@RequestMapping("/.well-known/est")
public class EnrollmentController {

    private final EntityDecoder<CertificationRequest> decoder;
    private final EntityEncoder<X509Certificate> encoder;
    private final EstMediatorImpl est;

    public EnrollmentController(@Qualifier("requestDecoder") EntityDecoder<CertificationRequest> decoder,
                                @Qualifier("dataEncoder") EntityEncoder<X509Certificate> encoder,
                                EstMediatorImpl est) {
        this.decoder = decoder;
        this.encoder = encoder;
        this.est = est;
    }


    //todo protect with spring security
    @PostMapping("/simpleenroll")
    public void doPost(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {

        enroll(request, response, (String) authentication.getPrincipal());
    }

    //Section 4.2.2
    //   The request Subject field
    //   and SubjectAltName extension MUST be identical to the corresponding
    //   fields in the certificate being renewed/rekeyed.  The
    //   ChangeSubjectName attribute, as defined in [RFC6402], MAY be included
    //   in the CSR to request that these fields be changed in the new
    //   certificate.
    @PostMapping("/simplereenroll")
    public void doReEnroll(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        //todo
        X509AuthenticationToken token = (X509AuthenticationToken) authentication.getCredentials();

        enroll(request, response, token.getAccountId());
    }

    private void enroll(HttpServletRequest request, HttpServletResponse response, String accountId) throws IOException {
        CertificationRequest csr = decoder.decode(new Base64InputStream(request.getInputStream()));

        try {
            response.setContentType(APPLICATION_PKCS7_MIME);
            response.addHeader("Content-Transfer-Encoding", "base64");
            X509Certificate certificate = est.enroll(csr, accountId);

            try (Base64OutputStream bOut = new Base64OutputStream(response.getOutputStream());) {
                new BouncyCastleSignedDataEncoder(new CMSSignedDataGenerator()).encode(bOut, certificate);
                //encoder.encode(bOut, certificate);
            }

        } catch (IOException e) {
            response.sendError(500);
            response.getWriter().write(e.getMessage());
            response.getWriter().close();

        }
    }
}
