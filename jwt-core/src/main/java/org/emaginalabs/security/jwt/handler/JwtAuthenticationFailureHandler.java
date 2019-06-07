package org.emaginalabs.security.jwt.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.proc.BadJWTException;
import org.emaginalabs.security.jwt.exceptions.JwtExpiredTokenException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Failure handler to jwt authentication
 */
//@Component
public class JwtAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private static final String SECURITY_COMPONENT = "SECURITY_COMPONENT";
    @Autowired(required = false)
    private ObjectMapper mapper = new ObjectMapper();


    public JwtAuthenticationFailureHandler() {
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException e) throws IOException, ServletException {

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        if (e.getClass().isAssignableFrom(BadCredentialsException.class)) {
            BadJWTException exception = new BadJWTException(e.getLocalizedMessage(), e);

            mapper.writeValue(response.getWriter(), exception);
        } else if (e.getClass().isAssignableFrom(JwtExpiredTokenException.class)) {

            BadJWTException exception = new BadJWTException("Authentication failed : " + e.getMessage(), e);
            mapper.writeValue(response.getWriter(), exception);

        } else {
            BadJWTException exception = new BadJWTException("Authentication failed: " + e.getMessage(), e);
            mapper.writeValue(response.getWriter(), exception);
        }
    }

}
