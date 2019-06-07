package org.emaginalabs.security.jwt.token.provider;

import org.springframework.security.core.userdetails.UserDetails;

import java.util.Map;

public interface JwtUserDetails extends UserDetails {

    /**
     * The claims of the entry for this user's account.
     *
     * @return the jwt´s claims
     */
    Map<String, Object> getClaims();
}
