package com.winllc.pki.est.server.controller;

import com.winllc.pki.est.server.EstMediatorImpl;
import com.winllc.ra.client.CertAuthorityConnection;
import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.codec.binary.Base64OutputStream;
import org.jscep.jester.CertificationRequest;
import org.jscep.jester.io.EntityDecoder;
import org.jscep.jester.io.EntityEncoder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.cert.X509Certificate;

import static com.winllc.pki.est.server.Constants.APPLICATION_PKCS7_MIME;


@Controller
@RequestMapping("/est")
public class EnrollmentController {

    @Autowired
    @Qualifier("requestDecoder")
    private EntityDecoder<CertificationRequest> decoder;
    @Autowired
    @Qualifier("dataEncoder")
    private EntityEncoder<X509Certificate> encoder;
    @Autowired
    private EstMediatorImpl est;


    //todo protect with spring security
    @PostMapping("/simpleenroll")
    public void doPost(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        enroll(request, response, authentication);
    }

    @PostMapping("/simplereenroll")
    public void doReEnroll(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException{
        enroll(request, response, authentication);
    }

    private void enroll(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        CertificationRequest csr = decoder.decode(new Base64InputStream(request.getInputStream()));

        try {
            response.setContentType(APPLICATION_PKCS7_MIME);
            response.addHeader("Content-Transfer-Encoding", "base64");
            X509Certificate certificate = est.enroll(csr, authentication.getName());
            try (Base64OutputStream bOut = new Base64OutputStream(response.getOutputStream());) {
                encoder.encode(bOut, certificate);
            }
        } catch (IOException e) {
            response.sendError(500);
            response.getWriter().write(e.getMessage());
            response.getWriter().close();

        }
    }
}
