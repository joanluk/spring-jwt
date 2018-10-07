package org.emaginalabs.security.jwt;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.emaginalabs.security.jwt.config.JwtSettings;
import org.emaginalabs.security.jwt.config.SkipPathRequestMatcher;
import org.emaginalabs.security.jwt.filter.JwtLoginProcessingFilter;
import org.emaginalabs.security.jwt.filter.JwtTokenAuthenticationProcessingFilter;
import org.emaginalabs.security.jwt.token.provider.TokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Utility class for configuring Security for your Spring API
 */
@Slf4j
@RequiredArgsConstructor
public class JwtWebSecurityConfigurer implements ApplicationContextAware {

    private static final String COMMA_SEPARATOR = ",";
    private static final String DEFAULT_PATH_SECURE = "/**";
    private static final String DEFAULT_PATH_LOGIN = "/login";
    private static final String GAIA_ENV_SECURITY_JWT_PATH_LOGIN = "gaia.env.security.jwt.path.login";
    private static final String APP_ENV_SECURITY_JWT_PATH_LOGIN = "app.env.security.jwt.path.login";
    private static final String APP_ENV_SECURITY_JQT_PATH_SECURE = "app.env.security.jqt.path.secure";
    private static final String GAIA_ENV_SECURITY_JWT_PATH_SECURE = "gaia.env.security.jwt.path.secure";
    private static final String GAIA_ENV_SECURITY_JWT_PATHS_ALLOW = "gaia.env.security.jwt.paths.allow";
    private static final String APP_ENV_SECURITY_JWT_PATHS_ALLOW = "app.env.security.jwt.paths.allow";

    @Autowired
    private AuthenticationManagerBuilder authenticationManager;

    private final AuthenticationFailureHandler jwtAuthenticationFailureHandler;

    private final TokenProvider jwtTokenProvider;

    private final JwtSettings jwtSettings;

    private ApplicationContext context;

    private final AuthenticationProvider jwtAuthenticationProvider;


    private JwtLoginProcessingFilter buildJwtLoginProcessingFilter(String loginEntryPoint) {
        log.debug("Configuring JwtLoginProcessingFilter...");
        return new JwtLoginProcessingFilter(loginEntryPoint, authenticationManager.getObject(), jwtTokenProvider, jwtSettings);
    }

    private JwtTokenAuthenticationProcessingFilter buildJwtTokenAuthenticationProcessingFilter(List<String> pathsToSkip, String pattern) {
        log.debug("Configuring JwtTokenAuthenticationProcessingFilter...");
        SkipPathRequestMatcher matcher = new SkipPathRequestMatcher(pathsToSkip, pattern);
        JwtTokenAuthenticationProcessingFilter filter
                = new JwtTokenAuthenticationProcessingFilter(matcher, jwtAuthenticationFailureHandler);
        filter.setAuthenticationManager(this.authenticationManager.getObject());
        return filter;
    }

    @PostConstruct
    public void configureProvider() {
        log.debug("Configuring provider to jwt security...");
        Assert.notNull(authenticationManager, "Authentication manager is null. It is not possible to add provider for jwt");
        authenticationManager.authenticationProvider(jwtAuthenticationProvider);
    }

    /**
     * Further configure the {@link HttpSecurity} object with some sensible defaults
     * by registering objects to obtain  urlLogin;a bearer token from a request.
     *
     * @param http configuration for Spring
     * @return the http configuration for further customizations
     * @throws Exception exception
     */
    @SuppressWarnings("unused")
    public void configure(HttpSecurity http) throws Exception {

        log.debug("Configuring http security for jwt security...");
        //get login path
        String loginPath = jwtSettings.getLoginPath();

        //get paths permits
        String permitPathsStr = jwtSettings.getPathAllow();

        List<String> permitPaths = new ArrayList<String>();
        if (StringUtils.hasText(permitPathsStr)) {
            Collections.addAll(Arrays.asList(permitPathsStr.split(COMMA_SEPARATOR)));
        }
        //add login path to exclude path filter
        permitPaths.add(permitPaths.size(), loginPath);
        //get path to authentication required
        String pathSecured = jwtSettings.getSecurePath();

        http
                //custom filter to login
                .addFilterBefore(buildJwtLoginProcessingFilter(loginPath), UsernamePasswordAuthenticationFilter.class)
                // Custom filter for authenticating users using tokens
                .addFilterBefore(buildJwtTokenAuthenticationProcessingFilter(permitPaths, pathSecured),
                        UsernamePasswordAuthenticationFilter.class)
                //exception handler jwt error
                .exceptionHandling()
                .authenticationEntryPoint(new JwtAuthenticationEntryPoint())
                .and()
                .httpBasic().disable();
    }


    @Override
    public void setApplicationContext(ApplicationContext applicationContext) {
        this.context = applicationContext;
    }
}
