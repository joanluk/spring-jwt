package org.emaginalabs.sample.jwt;

import org.emaginalabs.security.jwt.config.JwtConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@SpringBootApplication
@Import(JwtConfiguration.class)
@EnableSwagger2
public class SampleJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(SampleJwtApplication.class, args);
    }
}
