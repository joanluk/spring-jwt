package org.emaginalabs.sample.jwt.rest;

import org.emaginalabs.security.jwt.token.provider.JwtUserDetails;
import org.emaginalabs.security.jwt.token.provider.JwtUserDetailsImpl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * User: jose
 * Date: 2019-05-31
 * Time: 09:23
 */
@RestController
public class UserInfoController {

    @GetMapping("/api/info")
    public ResponseEntity<?> getInfoDetails() {

        if (SecurityContextHolder.getContext().getAuthentication() != null && (SecurityContextHolder.getContext().getAuthentication().isAuthenticated())) {
            Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            if (principal instanceof JwtUserDetails) {
                return ResponseEntity.ok().body((JwtUserDetailsImpl) principal);
            } else if (principal instanceof UserDetails)
                return ResponseEntity.ok().body(principal);
        }

        return ResponseEntity.noContent().build();
    }
}
