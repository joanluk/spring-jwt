package org.emaginalabs.sample.jwt.web;

import lombok.extern.slf4j.Slf4j;
import org.emaginalabs.security.jwt.claims.DefaultClaim;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.List;

@Configuration
@Slf4j
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
        log.debug("Configuring message converters");
        Jackson2ObjectMapperBuilder builder = new Jackson2ObjectMapperBuilder();
        builder.indentOutput(true).dateFormat(new SimpleDateFormat("yyyy-MM-dd"));
        converters.add(new MappingJackson2HttpMessageConverter(builder.build()));
    }

    @Bean
    UserDetailsService userDetailsService(BCryptPasswordEncoder passwordEncoder) {
        log.debug("Creating user detail service");

        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        User alice = new User("alice", passwordEncoder.encode("alice"),
                Arrays.asList(new SimpleGrantedAuthority("ROLE_Customer")));
        User bob = new User("bob", passwordEncoder.encode("bob"),
                Arrays.asList(new SimpleGrantedAuthority("ROLE_Publisher")));
        manager.createUser(alice);
        manager.createUser(bob);
        return manager;
    }

    @Bean
    BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    DefaultClaim customClaims() {
        DefaultClaim defaultClaim = new DefaultClaim();
        defaultClaim.put("claim1", "value-claims1");
        defaultClaim.put("claim2", "value-claims2");
        defaultClaim.put("claim3", "value-claims3");
        defaultClaim.put("claim4", "value-claims4");
        defaultClaim.put("claim5", "value-claims5");
        return defaultClaim;


    }

}
