package org.emaginalabs.security.jwt.token.provider;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.emaginalabs.security.jwt.token.model.JwtToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;

/**
 * Service that manipulates with Json Web Tokens
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
     * @return SignedJWT p null is no valid
     */
    SignedJWT validateToken(final String token);

    /**
     * Extract authentication from token
     *
     * @param token token to be extracted from
     * @return authentication details
     */
    Authentication getAuthentication(final String token);

    /**
     * Get username from token
     *
     * @param claims claims
     * @return String with username
     */
    String parseUsername(final JWTClaimsSet claims);

    /**
     * Get roles from token
     *
     * @param claims claims
     * @return List with roles of type {@link GrantedAuthority}
     */
    List<GrantedAuthority> parseRoles(final JWTClaimsSet claims);

    /**
     * Get all claims from token
     *
     * @param token token
     * @return all claims
     */
    JWTClaimsSet getJwtClaims(String token);


}
