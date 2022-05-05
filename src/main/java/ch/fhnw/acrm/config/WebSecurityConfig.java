/*
 * Copyright (c) 2019. University of Applied Sciences and Arts Northwestern Switzerland FHNW.
 * All rights reserved.
 */

package ch.fhnw.acrm.config;

import ch.fhnw.acrm.business.service.AgentService;
import ch.fhnw.acrm.data.domain.Agent;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import ch.fhnw.acrm.business.service.UserDetailsServiceImpl;
import onl.mrtn.security.config.EnableTokenSecurity;
import onl.mrtn.security.service.TokenService;
import onl.mrtn.security.web.CSRFRequestMatcher;
import onl.mrtn.security.web.TokenAuthenticationFilter;
import onl.mrtn.security.web.TokenLoginFilter;
import onl.mrtn.security.web.TokenLogoutHandler;

@EnableWebSecurity
@EnableTokenSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AgentService agentService;
    @Autowired
    private UserDetailsServiceImpl userDetailsService;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private TokenService tokenService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER).and()
            .requiresChannel().requestMatchers(r -> r.getHeader("X-Forwarded-Proto") != null).requiresSecure().and() // If the X-Forwarded-Proto header is present, redirect to HTTPS (Heroku)
            .csrf()
                .requireCsrfProtectionMatcher(new CSRFRequestMatcher())
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
            .authorizeRequests()
                .antMatchers("/", "/assets/**", "/user/**", "/login/**", "/swagger-ui/**", "/v3/api-docs/**", "/swagger-resources/**").permitAll() // Show Pages without authentication
                .antMatchers(HttpMethod.GET, "/logout").permitAll()
                .antMatchers("/profile/edit").hasRole("USER")
                .anyRequest().authenticated()
                .and()
                .addFilter(new TokenLoginFilter(authenticationManagerBean(), tokenService))
                .addFilter(new TokenAuthenticationFilter(authenticationManagerBean(), tokenService))
            .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/")
                .addLogoutHandler(new TokenLogoutHandler(tokenService));
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
        Agent sysAdmin = new Agent();
        sysAdmin.setEmail("system@admin.com");
        sysAdmin.setPassword("password");
       // sysAdmin.setRole("SYSTEM_ADMINISTRATOR");
        sysAdmin.setName("System Administrator");
        agentService.saveAgent(sysAdmin);
    }

    @Bean(name = BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}