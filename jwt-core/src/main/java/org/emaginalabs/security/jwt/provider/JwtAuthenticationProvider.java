package org.emaginalabs.security.jwt.provider;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.emaginalabs.security.jwt.JwtTokenAuthentication;
import org.emaginalabs.security.jwt.token.model.JwtToken;
import org.emaginalabs.security.jwt.token.provider.TokenProvider;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;


/**
 * An {@link AuthenticationProvider} implementation that will use provided
 * instance of {@link JwtToken} to perform authentication.
 */
@Slf4j
@RequiredArgsConstructor
@SuppressWarnings("unchecked")
public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final TokenProvider tokenProvider;


    @Override
    public Authentication authenticate(Authentication authentication) {
        log.debug("Init process authenticate with jwt");
        String token = (String) authentication.getCredentials();

        return tokenProvider.getAuthentication(token);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (JwtTokenAuthentication.class.isAssignableFrom(authentication));
    }

}