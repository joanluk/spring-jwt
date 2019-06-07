package org.emaginalabs.security.jwt.config;


import lombok.extern.slf4j.Slf4j;
import org.emaginalabs.security.jwt.JwtAuthenticationEntryPoint;
import org.emaginalabs.security.jwt.handler.JwtAuthenticationFailureHandler;
import org.emaginalabs.security.jwt.provider.JwtAuthenticationProvider;
import org.emaginalabs.security.jwt.token.provider.JwtTokenProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;

/**
 * Configuration jwt authentication in GAIA Application
 * <p>
 * This class only active when property 'app.env.security.authentication' is equal to 'jwt'
 */
@Configuration
//@ConditionalOnProperty(name = "app.env.security.authentication.type", havingValue = "jwt")
@Slf4j
public class JwtConfiguration {

    @ConditionalOnMissingBean
    @Bean
    public JwtSettings jwtSettings() {
        return new JwtSettings();
    }

    @ConditionalOnMissingBean
    @Bean
    public JwtTokenProvider jwtTokenProvider() {
        return new JwtTokenProvider(jwtSettings());
    }

    @ConditionalOnMissingBean
    @Bean
    public AuthenticationProvider jwtAuthenticationProvider() {
        return new JwtAuthenticationProvider(jwtTokenProvider());
    }

    @ConditionalOnMissingBean
    @Bean
    public JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint() {
        return new JwtAuthenticationEntryPoint();
    }

    @ConditionalOnMissingBean
    @Bean
    public JwtAuthenticationFailureHandler jwtAuthenticationFailureHandler() {
        return new JwtAuthenticationFailureHandler();
    }

    @ConditionalOnMissingBean
    //@ConditionalOnBean(AuthenticationManagerBuilder.class)
    @Bean
    public JwtWebSecurityConfigurer jwtWebSecurityConfigurer() {
        return new JwtWebSecurityConfigurer(
                jwtAuthenticationFailureHandler(),
                jwtTokenProvider(),
                jwtSettings(),
                jwtAuthenticationProvider());
    }


}
