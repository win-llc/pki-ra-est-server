package com.winllc.pki.est.server.config;

import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.jscep.jester.io.BouncyCastleCertificateRequestDecoder;
import org.jscep.jester.io.BouncyCastleCsrAttributeEncoder;
import org.jscep.jester.io.BouncyCastleSignedDataDecoder;
import org.jscep.jester.io.BouncyCastleSignedDataEncoder;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan("com.winllc.pki.est.server")
public class AppConfig {

    public static void main(String[] args){
        SpringApplication.run(AppConfig.class, args);
    }

    @Bean
    public CMSSignedDataGenerator signedDataGenerator(){
        return new CMSSignedDataGenerator();
    }

    @Bean("dataEncoder")
    public BouncyCastleSignedDataEncoder dataEncoder(CMSSignedDataGenerator generator){
        return new BouncyCastleSignedDataEncoder(generator);
    }

    @Bean("dataDecoder")
    public BouncyCastleSignedDataDecoder dataDecoder(){
        return new BouncyCastleSignedDataDecoder();
    }

    @Bean("requestDecoder")
    public BouncyCastleCertificateRequestDecoder requestDecoder(){
        return new BouncyCastleCertificateRequestDecoder();
    }

    @Bean("entityEncoder")
    public BouncyCastleCsrAttributeEncoder entityEncoder(){
        return new BouncyCastleCsrAttributeEncoder();
    }

}
