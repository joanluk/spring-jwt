package org.emaginalabs.security.jwt.exceptions;

import org.springframework.security.core.AuthenticationException;

/**
 * User: jose
 * Date: 2019-03-23
 * Time: 17:00
 */
public class InvalidJWTException extends AuthenticationException {


    public InvalidJWTException(String message) {
        super(message);
    }

    public InvalidJWTException(String message, Throwable cause) {
        super(message, cause);
    }
}
