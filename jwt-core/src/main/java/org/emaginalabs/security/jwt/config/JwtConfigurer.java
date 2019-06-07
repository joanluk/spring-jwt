package org.emaginalabs.security.jwt.config;

import lombok.extern.slf4j.Slf4j;
import org.emaginalabs.security.jwt.JwtAuthenticationEntryPoint;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * User: jose
 * Date: 2019-05-30
 * Time: 10:50
 */

@Slf4j
public class JwtConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private static final String COMMA_SEPARATOR = ",";

    private JwtWebSecurityConfigurer configurer;

    public JwtConfigurer(JwtWebSecurityConfigurer jwtWebSecurityConfigurer) {
        this.configurer = jwtWebSecurityConfigurer;

    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        log.debug("Configuring http security for jwt security...");
        //get login path
        String loginPath = configurer.getJwtSettings().getLoginPath();

        //get paths permits
        String permitPathsStr = configurer.getJwtSettings().getPathAllow();

        List<String> permitPaths = new ArrayList<String>();
        if (StringUtils.hasText(permitPathsStr)) {
            Collections.addAll(Arrays.asList(permitPathsStr.split(COMMA_SEPARATOR)));
        }
        //add login path to exclude path filter
        permitPaths.add(permitPaths.size(), loginPath);
        //get path to authentication required
        String pathSecured = configurer.getJwtSettings().getSecurePath();
        if (configurer.getJwtSettings().isApiLoginEnabled()) {
            //custom filter to login
            http.addFilterBefore(configurer.buildJwtLoginProcessingFilter(loginPath), UsernamePasswordAuthenticationFilter.class);
        }
        http
                // Custom filter for authenticating users using tokens
                .addFilterAfter(configurer.buildJwtTokenAuthenticationProcessingFilter(permitPaths, pathSecured),
                        UsernamePasswordAuthenticationFilter.class)
                //exception handler jwt error
                .exceptionHandling()
                .authenticationEntryPoint(new JwtAuthenticationEntryPoint());
    }

}
