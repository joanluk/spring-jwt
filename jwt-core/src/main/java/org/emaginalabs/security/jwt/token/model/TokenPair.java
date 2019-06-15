package org.emaginalabs.security.jwt.token.model;

import com.fasterxml.jackson.annotation.JsonProperty;


public class TokenPair {

    private final String jwt;

    @JsonProperty("refresh_token")
    private final String refreshToken;

    public TokenPair(String jwt, String refreshToken) {
        this.jwt = jwt;
        this.refreshToken = refreshToken;
    }

    public String getJwt() {
        return jwt;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

}
