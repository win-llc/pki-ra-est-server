package com.winllc.ra.est.config;

import com.winllc.acme.common.client.ApiClient;
import com.winllc.ra.est.security.CustomAuthenticationProvider;
import com.winllc.ra.est.security.CustomX509AuthFilter;
import com.winllc.ra.est.security.ServerDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;

//@Configuration
//@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationEntryPoint authEntryPoint;
    @Autowired
    private CustomAuthenticationProvider customAuthenticationProvider;
    @Autowired
    private ServerDetailsService serverDetailsService;
    @Autowired
    private ApiClient apiClient;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/.well-known/est/simpleenroll", "/.well-known/est/simplereenroll").authenticated()
                .antMatchers("/.well-known/est/**").permitAll()
                .antMatchers("/actuator/**").permitAll()
                .and()
                .httpBasic()
                .authenticationEntryPoint(authEntryPoint)
                .and().x509()
                .subjectPrincipalRegex("CN=(.*?)(?:,|$)")
                .x509AuthenticationFilter(customX509AuthFilter())
        .userDetailsService(serverDetailsService)
        ;
    }

    //@Bean
    public CustomX509AuthFilter customX509AuthFilter() throws Exception {
        CustomX509AuthFilter filter = new CustomX509AuthFilter(apiClient);
        filter.setAuthenticationManager(authenticationManagerBean());
        return filter;
    }


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(customAuthenticationProvider);
    }

    //@Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    //@Bean
    @Override
    public UserDetailsService userDetailsService() {
        //todo replace with details service that checks if server entry is tied to a valid account on the RA
        UserDetails user =
                User.withDefaultPasswordEncoder()
                        .username("CN=est-test.winllc-dev.com,OU=Servers,DC=winllc-dev,DC=com")
                        .password("password")
                        .roles("USER")
                        .build();

        return new InMemoryUserDetailsManager(user);
    }
}
