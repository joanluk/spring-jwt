package org.emaginalabs.security.jwt.token.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.jsonwebtoken.Claims;

/**
 * Raw representation of JWT Token.
 */
public final class AccessJwtToken implements JwtToken {

    private final String rawToken;
    @JsonIgnore
    private final Claims claims;

    public AccessJwtToken(final String token, Claims claims) {
        this.rawToken = token;
        this.claims = claims;
    }

    public String getToken() {
        return this.rawToken;
    }

    public Claims getClaims() {
        return claims;
    }
}