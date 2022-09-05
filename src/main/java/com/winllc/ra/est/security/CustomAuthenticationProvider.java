package com.winllc.ra.est.security;

import com.winllc.acme.common.client.ApiClient;
import com.winllc.acme.common.client.api.ValidationServiceApi;
import com.winllc.acme.common.client.model.RAAccountValidationResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private static final Logger log = LogManager.getLogger(CustomAuthenticationProvider.class);

    private final ApiClient apiClient;

    public CustomAuthenticationProvider(ApiClient apiClient) {
        this.apiClient = apiClient;
    }

    @Override
    public Authentication authenticate(Authentication auth)
            throws AuthenticationException {
        String username = auth.getName();
        String password = auth.getCredentials().toString();

        boolean valid = false;
        try {
            ValidationServiceApi validationServiceApi = new ValidationServiceApi(apiClient);
            RAAccountValidationResponse raAccountValidationResponse
                    = validationServiceApi.validateAccountCredentials(username, password);

            valid = raAccountValidationResponse.isValid();
        } catch (Exception e) {
            log.error("Could not validate client", e);
        }

        if(valid){
            log.info("Account authenticated: "+username);
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