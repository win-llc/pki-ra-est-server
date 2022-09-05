package com.winllc.ra.est.config;

import com.winllc.ra.est.io.BouncyCastleCertificateRequestDecoder;
import com.winllc.ra.est.io.BouncyCastleCsrAttributeEncoder;
import com.winllc.ra.est.io.BouncyCastleSignedDataDecoder;
import com.winllc.ra.est.io.BouncyCastleSignedDataEncoder;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.data.mongo.MongoDataAutoConfiguration;
import org.springframework.boot.autoconfigure.mongo.MongoAutoConfiguration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.web.filter.ShallowEtagHeaderFilter;

import java.util.Arrays;

@SpringBootApplication(
        exclude = {
                MongoAutoConfiguration.class,
                MongoDataAutoConfiguration.class
        }
)
@ComponentScan("com.winllc.ra.est")
public class AppConfig {

    public static void main(String[] args){
        SpringApplication.run(AppConfig.class, args);
    }

    @Bean
    public FilterRegistrationBean filterRegistrationBean() {
        FilterRegistrationBean filterBean = new FilterRegistrationBean();
        filterBean.setFilter(new ShallowEtagHeaderFilter());
        filterBean.setUrlPatterns(Arrays.asList("*"));
        return filterBean;
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
