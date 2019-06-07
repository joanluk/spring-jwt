package org.emaginalabs.sample.jwt.web;

import lombok.extern.slf4j.Slf4j;
import org.emaginalabs.security.jwt.config.JwtConfigurer;
import org.emaginalabs.security.jwt.config.JwtWebSecurityConfigurer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@Slf4j
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private static final String ROLE_USER = "USER";
    private static final String ROLE_ADMIN = "ADMIN";

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    JwtWebSecurityConfigurer jwtConfigurer;


    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        log.debug("Configuring security");

        httpSecurity
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .cors()
                .and()
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/api/info/**").permitAll()
                .antMatchers(HttpMethod.GET, "/api/pets/**").authenticated()
                .antMatchers(HttpMethod.POST, "/api/pets/**").hasAnyRole("ROLE_Publisher")
                .anyRequest().authenticated()
                .and()
                .httpBasic()
                .and()
                .apply(new JwtConfigurer(jwtConfigurer));

    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        log.debug("Configuring AuthenticationManager");

        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
        log.info("configure demo security application");
        User.UserBuilder users = User.builder();
        User user = (User) users
                .username("user")
                .password("user")
                .roles(ROLE_USER)
                .build();
        User admin = (User) users
                .username("admin")
                .password("admin")
                .roles(ROLE_ADMIN)
                .build();
        User ugaia1 = (User) users
                .username("UGAIA1")
                .password("UGAIA1")
                .roles(ROLE_USER, ROLE_ADMIN)
                .build();
        auth.inMemoryAuthentication().withUser(user).withUser(admin).withUser(ugaia1).passwordEncoder(passwordEncoder());
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
        return source;
    }

    @Bean
    public static NoOpPasswordEncoder passwordEncoder() {
        return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
    }
    
}
