package org.emaginalabs.security.jwt.token.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.nimbusds.jwt.JWTClaimsSet;

/**
 * Raw representation of JWT Token.
 */
public final class AccessJwtToken implements JwtToken {

    private final String rawToken;
    @JsonIgnore
    private final JWTClaimsSet claims;

    public AccessJwtToken(final String token, JWTClaimsSet claims) {
        this.rawToken = token;
        this.claims = claims;
    }

    public String getToken() {
        return this.rawToken;
    }

    public JWTClaimsSet getClaims() {
        return claims;
    }
}