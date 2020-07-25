package com.winllc.pki.est.server.config;

import com.winllc.ra.client.AccountProviderConnection;
import com.winllc.ra.client.CertAuthorityConnection;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RAConnectionConfig {

    @Value("${win-ra.base-url}")
    private String winRaBaseUrl;

    @Bean
    public CertAuthorityConnection certAuthorityConnection(){
        CertAuthorityConnection connection = new CertAuthorityConnection(winRaBaseUrl, "dogtag");

        return connection;
    }

    @Bean
    public AccountProviderConnection accountProviderConnection(){
        AccountProviderConnection accountProviderConnection = new AccountProviderConnection(winRaBaseUrl);

        return accountProviderConnection;
    }
}
