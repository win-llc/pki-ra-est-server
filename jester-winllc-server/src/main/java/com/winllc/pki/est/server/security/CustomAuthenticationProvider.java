package com.winllc.pki.est.server.security;

import com.winllc.ra.client.ApiClient;
import com.winllc.ra.client.api.ValidationServiceApi;
import com.winllc.ra.client.model.RAAccountValidationResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.Collections;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private ApiClient apiClient;

    @Override
    public Authentication authenticate(Authentication auth)
            throws AuthenticationException {
        String username = auth.getName();
        String password = auth.getCredentials()
                .toString();

        boolean valid = false;
        try {
            ValidationServiceApi validationServiceApi = new ValidationServiceApi(apiClient);
            RAAccountValidationResponse raAccountValidationResponse
                    = validationServiceApi.validateAccountCredentials(username, password);

            valid = raAccountValidationResponse.isValid();
        } catch (Exception e) {
            e.printStackTrace();
        }

        if(valid){
            System.out.println("Account authenticated");
            return new UsernamePasswordAuthenticationToken
                    (username, password, new ArrayList<>());
        }else{
            throw new
                    BadCredentialsException("External system authentication failed");
        }
    }

    @Override
    public boolean supports(Class<?> auth) {
        return auth.equals(UsernamePasswordAuthenticationToken.class);
    }
}