package com.winllc.pki.est.server.controller;

import org.jscep.jester.CertificationRequest;
import org.jscep.jester.EstMediator;
import org.jscep.jester.io.EntityDecoder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
@RequestMapping("/.well-known/est")
public class KeyGenerationController {

    @Autowired
    private EstMediator est;
    @Autowired
    private EntityDecoder<CertificationRequest> decoder;

    @PostMapping("/serverkeygen")
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        CertificationRequest csr = decoder.decode(request.getInputStream());

        //todo

        response.getWriter().write(csr.toString());
    }

}
