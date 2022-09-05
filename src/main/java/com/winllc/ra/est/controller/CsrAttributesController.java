package com.winllc.ra.est.controller;

import com.winllc.ra.est.io.EntityEncoder;
import com.winllc.ra.est.protocol.EstMediator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.winllc.ra.est.Constants.APPLICATION_CSRATTRS;

@Controller
@RequestMapping("/.well-known/est")
public class CsrAttributesController {

    @Autowired
    private EstMediator est;
    @Autowired
    private EntityEncoder<String> encoder;

    @GetMapping("/csrattrs")
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String[] attrs = est.getCsrAttributes();
        if (attrs.length == 0) {
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);

        } else {
            response.setContentType(APPLICATION_CSRATTRS);

            encoder.encode(response.getOutputStream(), attrs);
        }
    }
}
