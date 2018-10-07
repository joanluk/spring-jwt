package org.emaginalabs.sample.jwt;

import org.emaginalabs.security.jwt.EnableJwtSecurity;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@SpringBootApplication
@EnableJwtSecurity
//@Import(JwtConfiguration.class)
@EnableSwagger2
public class SampleJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(SampleJwtApplication.class, args);
    }
}
