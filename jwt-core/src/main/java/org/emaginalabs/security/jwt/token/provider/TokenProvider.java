package org.emaginalabs.security.jwt.token.provider;

import org.emaginalabs.security.jwt.token.model.JwtToken;
import org.springframework.security.core.Authentication;

/**
 * Service that manipulates with Json Web Tokens
 *
 * @since 1.0
 *
 * @author Arquitectura
 */
public interface TokenProvider {


    /**
     * Creates token based on authentication details
     *
     * @param authentication authenticatioon details
     * @return json web token
     */
    JwtToken createToken(final Authentication authentication);

    /**
     * Checks whether token is valid
     *
     * @param token token to be checked
     * @return boolean true if valid
     */
    boolean validateToken(final String token);

    /**
     * Extract authentication from token
     *
     * @param token token to be extracted from
     * @return authentication details
     */
    Authentication getAuthentication(final String token);


}
