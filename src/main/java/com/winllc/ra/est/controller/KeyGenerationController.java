package com.winllc.ra.est.controller;

import com.winllc.acme.common.util.CertUtil;
import com.winllc.ra.est.io.EntityDecoder;
import com.winllc.ra.est.protocol.CertificationRequest;
import com.winllc.ra.est.protocol.EstMediator;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.winllc.ra.est.Constants.APPLICATION_PKCS7_MIME;

@Controller
@RequestMapping("/.well-known/est")
public class KeyGenerationController {

    @Autowired
    private EstMediator est;
    @Autowired
    private EntityDecoder<CertificationRequest> decoder;

    @PostMapping("/serverkeygen")
    public void doPost(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        CertificationRequest csr = decoder.decode(request.getInputStream());

        //todo
        response.getWriter().write(csr.toString());

        try {
            CertUtil.generateRSAKeyPair();

            response.setContentType(APPLICATION_PKCS7_MIME);
            response.addHeader("Content-Transfer-Encoding", "base64");
            //X509Certificate certificate = est.enroll(csr, authentication.getName());


        } catch (Exception e) {
            response.sendError(500);
            response.getWriter().write(e.getMessage());
            response.getWriter().close();

        }
    }

}
