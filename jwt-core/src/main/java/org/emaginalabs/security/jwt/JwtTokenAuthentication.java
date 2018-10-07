package org.emaginalabs.security.jwt;

import org.springframework.security.authentication.AbstractAuthenticationToken;


/**
 * An {@link org.springframework.security.core.Authentication} implementation
 * that is designed for simple presentation of JwtToken.
 */
public class JwtTokenAuthentication extends AbstractAuthenticationToken {
    private static final long serialVersionUID = 2877954820905567501L;
    private String rawToken;

    public JwtTokenAuthentication(String unsafeToken) {
        super(null);
        this.rawToken = unsafeToken;
        this.setAuthenticated(false);
    }


    @Override
    public void setAuthenticated(boolean authenticated) {
        if (authenticated) {
            throw new IllegalArgumentException(
                    "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        }
        super.setAuthenticated(false);
    }

    @Override
    public Object getCredentials() {
        return rawToken;
    }

    /**
     * The identity of the principal being authenticated. In the case of an authentication
     * request with username and password, this would be the username. Callers are
     * expected to populate the principal for an authentication request.
     * <p>
     * The <tt>AuthenticationManager</tt> implementation will often return an
     * <tt>Authentication</tt> containing richer information as the principal for use by
     * the application. Many of the authentication providers will create a
     * {@code UserDetails} object as the principal.
     *
     * @return the <code>Principal</code> being authenticated or the authenticated
     * principal after authentication.
     */
    @Override
    public Object getPrincipal() {
        return rawToken;
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        this.rawToken = null;
    }
}