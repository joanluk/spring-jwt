package org.emaginalabs.security.jwt.token.provider;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

import java.util.*;

/**
 * A UserDetails implementation which is used internally from JWT token.
 *
 * @author Arqutiectura
 */
public class JwtUserDetailsImpl implements JwtUserDetails {

    private String password;
    private String username;
    private Collection<GrantedAuthority> authorities = AuthorityUtils.NO_AUTHORITIES;
    private boolean accountNonExpired = true;
    private boolean accountNonLocked = true;
    private boolean credentialsNonExpired = true;
    private boolean enabled = true;

    private Map<String, Object> claims;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    public Map<String, Object> getClaims() {
        return claims;
    }


    // ~ Inner Classes
    // ==================================================================================================

    /**
     * Variation of essence pattern. Used to create mutable intermediate object
     */
    public static class Essence {
        protected JwtUserDetailsImpl instance = createTarget();
        private List<GrantedAuthority> mutableAuthorities = new ArrayList<GrantedAuthority>();

        public Essence() {
        }


        protected JwtUserDetailsImpl createTarget() {
            return new JwtUserDetailsImpl();
        }

        /**
         * Adds the authority to the list, unless it is already there, in which case it is
         * ignored
         */
        public void addAuthority(GrantedAuthority a) {
            if (!hasAuthority(a)) {
                mutableAuthorities.add(a);
            }
        }

        private boolean hasAuthority(GrantedAuthority a) {
            for (GrantedAuthority authority : mutableAuthorities) {
                if (authority.equals(a)) {
                    return true;
                }
            }
            return false;
        }

        public UserDetails createUserDetails() {
            Assert.notNull(instance,
                    "Essence can only be used to create a single instance");
            Assert.notNull(instance.username, "username must not be null");

            instance.authorities = Collections.unmodifiableList(mutableAuthorities);

            UserDetails newInstance = instance;

            instance = null;

            return newInstance;
        }

        public Collection<GrantedAuthority> getGrantedAuthorities() {
            return mutableAuthorities;
        }

        public void setAccountNonExpired(boolean accountNonExpired) {
            instance.accountNonExpired = accountNonExpired;
        }

        public void setAccountNonLocked(boolean accountNonLocked) {
            instance.accountNonLocked = accountNonLocked;
        }

        public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
            mutableAuthorities = new ArrayList<GrantedAuthority>();
            mutableAuthorities.addAll(authorities);
        }

        public void setCredentialsNonExpired(boolean credentialsNonExpired) {
            instance.credentialsNonExpired = credentialsNonExpired;
        }

        public void setEnabled(boolean enabled) {
            instance.enabled = enabled;
        }

        public void setPassword(String password) {
            instance.password = password;
        }

        public void setUsername(String username) {
            instance.username = username;
        }

        public void setClaims(Map<String, Object> claims) {
            instance.claims = Collections.unmodifiableMap(claims);
        }

    }
}
