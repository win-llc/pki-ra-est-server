package com.winllc.pki.est.server.security;

import com.winllc.ra.client.AccountProviderConnection;
import com.winllc.ra.client.CertAuthorityConnection;
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
    private AccountProviderConnection accountProviderConnection;

    @Override
    public Authentication authenticate(Authentication auth)
            throws AuthenticationException {
        String username = auth.getName();
        String password = auth.getCredentials()
                .toString();

        boolean valid = false;
        try {
            valid = accountProviderConnection.validateAccountCredentials(username, password);
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