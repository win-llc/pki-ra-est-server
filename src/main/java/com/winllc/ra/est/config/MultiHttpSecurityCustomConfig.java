package com.winllc.ra.est.config;

import com.winllc.acme.common.client.ApiClient;
import com.winllc.ra.est.security.CustomAuthenticationProvider;
import com.winllc.ra.est.security.CustomX509AuthFilter;
import com.winllc.ra.est.security.ServerDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.AuthenticationEntryPoint;

@EnableWebSecurity
public class MultiHttpSecurityCustomConfig {


    @Configuration
    @Order(1)
    public static class X509LoginSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

        @Autowired
        private ApiClient apiClient;
        @Autowired
        private ServerDetailsService serverDetailsService;

        protected void configure(HttpSecurity http) throws Exception {
            http
                    .antMatcher("/.well-known/est/simplereenroll").authorizeRequests()
                    .anyRequest().authenticated()

                    .and().x509()
                    //.subjectPrincipalRegex("CN=(.*?)(?:,|$)")
                    .x509AuthenticationFilter(customX509AuthFilter())
                    .userDetailsService(serverDetailsService)
                    .and()
                    .csrf().disable()
            ;
        }

        @Bean
        public CustomX509AuthFilter customX509AuthFilter() throws Exception {
            CustomX509AuthFilter filter = new CustomX509AuthFilter(apiClient);
            filter.setAuthenticationManager(authenticationManagerBean());
            return filter;
        }
    }

    @Configuration
    @Order(2)
    public static class BasicLoginWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

        @Autowired
        private CustomAuthenticationProvider customAuthenticationProvider;
        @Autowired
        private AuthenticationEntryPoint authEntryPoint;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .antMatcher("/.well-known/est/simpleenroll").authorizeRequests()
                    .anyRequest().authenticated()
                    .and()
                    .httpBasic()
                    .authenticationEntryPoint(authEntryPoint)
                    .and()
                    .csrf().disable()
            ;
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.authenticationProvider(customAuthenticationProvider);
        }
    }

    @Configuration
    @Order(3)
    public static class NoLoginWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests().antMatchers("/**").permitAll()
            ;
        }
    }


}