package com.winllc.ra.est.controller;

import com.winllc.ra.est.io.EntityEncoder;
import com.winllc.ra.est.protocol.EstMediator;
import org.apache.commons.codec.binary.Base64OutputStream;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.cert.X509Certificate;

import static com.winllc.ra.est.Constants.APPLICATION_PKCS7_MIME;

@Controller
@RequestMapping("/.well-known/est")
public class CaDistributionController {

    @Autowired
    private EstMediator est;
    @Autowired
    private EntityEncoder<X509Certificate> encoder;

    @GetMapping("/cacerts")
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType(APPLICATION_PKCS7_MIME);
        response.addHeader("Content-Transfer-Encoding", "base64");

        try(Base64OutputStream bOut = new Base64OutputStream(response.getOutputStream());){
            encoder.encode(bOut, est.getCaCertificates());
        }
    }

}
