package org.emaginalabs.security.jwt;


import org.emaginalabs.security.jwt.config.JwtConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
@Import(JwtConfiguration.class)
public @interface EnableJwtSecurity {

}
