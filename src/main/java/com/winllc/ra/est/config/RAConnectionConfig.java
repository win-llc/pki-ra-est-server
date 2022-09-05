package com.winllc.ra.est.config;

import com.winllc.acme.common.client.ApiClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RAConnectionConfig {

    @Value("${win-ra.base-url}")
    private String winRaBaseUrl;


    @Bean
    public ApiClient apiClient(){
        ApiClient apiClient = new ApiClient();
        apiClient.setBasePath(winRaBaseUrl);
        return apiClient;
    }

}
