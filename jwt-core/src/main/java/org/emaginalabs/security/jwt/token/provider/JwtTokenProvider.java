package org.emaginalabs.security.jwt.token.provider;

import io.jsonwebtoken.*;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.impl.compression.DefaultCompressionCodecResolver;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.emaginalabs.security.jwt.config.JwtSettings;
import org.emaginalabs.security.jwt.exceptions.JwtExpiredTokenException;
import org.emaginalabs.security.jwt.token.model.AccessJwtToken;
import org.emaginalabs.security.jwt.token.model.JwtToken;
import org.joda.time.LocalDateTime;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.Assert;

import javax.annotation.PostConstruct;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Class that manipulates with Json Web Tokens
 * Responsible for generating and parsing tokens jwt. also offers utilities on information to recover from a token
 */

@Slf4j
@RequiredArgsConstructor
public class JwtTokenProvider implements TokenProvider {

    public static final String TOKEN_PREFIX = "Bearer";            // the prefix of the token in the http header
    public static final String AUTHENTICATION_HEADER_NAME = "Authorization";    // the http header containing the prexif + the token
    private static final String ROLE_CLAIMS = "authorities";

    @Value("${app.env.name:unknow-application}")
    private String appName;

    private final JwtSettings settings;

    @Autowired(required = false)
    private Claims customClaims;

    private KeyHolder keyHolder;

    /**
     * Creates token based on authentication details
     *
     * @param authentication Authentication
     * @return The generated token.
     */
    @SuppressWarnings("unchecked")
    public JwtToken createToken(final Authentication authentication) {
        Assert.hasText(authentication.getName(), "Cannot create JWT Token without username");

        //TODO ver si se define clase encargada de dar la fecha
        LocalDateTime currentTime = LocalDateTime.now();

        Claims claims = Jwts.claims().setSubject(authentication.getName());
        claims.put(ROLE_CLAIMS, getAuthoritiesStr((List<GrantedAuthority>) authentication.getAuthorities()));

        JwtBuilder jwtBuilder = Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setAudience(appName)
                .setSubject(authentication.getName())
                .setIssuedAt(currentTime.toDate())
                .setExpiration(currentTime.plusMinutes(settings.getRefreshTokenExpTime()).toDate());

        if (keyHolder.getSecret() != null) {
            jwtBuilder = jwtBuilder.signWith(settings.getSignatureAlgorithm(), keyHolder.getSecret());
        } else {
            jwtBuilder = jwtBuilder.signWith(settings.getSignatureAlgorithm(), keyHolder.getPrivateKey());
        }

        jwtBuilder.claim(ROLE_CLAIMS, getAuthoritiesStr((List<GrantedAuthority>) authentication.getAuthorities()));
        /* compression */
        if (settings.isCompresion()) {
            jwtBuilder.compressWith(CompressionCodecs.DEFLATE);
        }
        //custom claims
        if (customClaims != null) {
            log.debug("including custom claims defined by the bean {0}", customClaims.getClass().getName());
            jwtBuilder.addClaims(customClaims);

        }
        String token = jwtBuilder.compact();
        log.debug("Access token created: {)", token);
        return new AccessJwtToken(token, claims);

    }


    public Jws<Claims> validateToken(String token) {
        try {
            if (keyHolder.getSecret() != null) {
                return Jwts.parser().setSigningKey(settings.getTokenSigningKey()).parseClaimsJws(
                        token.replace(TOKEN_PREFIX, ""));

            } else {
                return Jwts.parser().setSigningKey(keyHolder.publicKey).parseClaimsJws(
                        token.replace(TOKEN_PREFIX, ""));

            }
        } catch (Exception ex) {
            log.error("Invalid JWT Token", ex);
            return null;
        }
    }

    /**
     * Extract authentication from token
     *
     * @param token token to be extracted from
     * @return authentication details
     */
    @Override
    public Authentication getAuthentication(String token) {

        if (token != null && token.startsWith(JwtTokenProvider.TOKEN_PREFIX)) {
            Jws<Claims> claims = validateToken(token);
            String user = parseUsername(claims);
            List<GrantedAuthority> authorities = parseRoles(claims);
            //TODO si se han incluido algunos otros claims no se setean en el objeto de seguridad
            if (user != null) {
                return new UsernamePasswordAuthenticationToken(user, null, authorities);
            }
        }

        return null;
    }

    /**
     * Parse a token and extract the subject (username).
     *
     * @param claims claims jwt.
     * @return The subject (username) of the token.
     */
    public String parseUsername(Jws<Claims> claims) {

        return claims
                .getBody()
                .getSubject();

    }

    @SuppressWarnings("unchecked")
    public List<GrantedAuthority> parseRoles(Jws<Claims> claims) {

        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        List<String> roles = (List<String>) claims
                .getBody()
                .get(ROLE_CLAIMS);

        for (String role : roles) {
            authorities.add(new SimpleGrantedAuthority(role));
        }
        return authorities;
    }

    private List<String> getAuthoritiesStr(final List<GrantedAuthority> authorities) {
        List<String> authoritiesStr = new ArrayList<String>();
        for (GrantedAuthority authority : authorities) {
            authoritiesStr.add(authority.getAuthority());
        }
        return authoritiesStr;
    }

    /**
     * Return claims body
     *
     * @param claims claims jwt
     * @return Content body
     */
    public Claims parseBody(final Jws<Claims> claims) {
        return claims
                .getBody();
    }

    public JwsHeader getHeader(final Jws<Claims> claims) {
        return claims
                .getHeader();
    }


    public Jws<Claims> getJwtClaims(final String token) {

        JwtParser jwtParser = Jwts.parser()
                .setSigningKey(settings.getTokenSigningKey());
        if (settings.isCompresion()) {
            jwtParser.setCompressionCodecResolver(new DefaultCompressionCodecResolver());
        }
        try {
            return jwtParser.parseClaimsJws(token.replace(TOKEN_PREFIX, ""));
        } catch (UnsupportedJwtException ex) {
            log.error("Invalid JWT Token", ex);
            throw new BadCredentialsException("Invalid JWT token. ", ex);
        } catch (MalformedJwtException ex) {
            log.error("Invalid JWT Token", ex);
            throw new BadCredentialsException("Invalid JWT token. ", ex);
        } catch (IllegalArgumentException ex) {
            log.error("Invalid JWT Token", ex);
            throw new BadCredentialsException("Invalid JWT token. ", ex);
        } catch (SignatureException ex) {
            log.error("Invalid JWT Token", ex);
            throw new BadCredentialsException("Invalid JWT token. ", ex);
        } catch (ExpiredJwtException expiredEx) {
            log.info("JWT Token is expired", expiredEx);
            throw new JwtExpiredTokenException(token, "JWT Token expired.", expiredEx);
        }

    }

    /**
     * Return private claim with name defined in claim property
     *
     * @param claim name claim to obtain
     * @param token token
     * @return info of claim
     */
    public Object parseCustomClaim(final String token, final String claim) {
        return getJwtClaims(token)
                .getBody()
                .get(claim);
    }


    @PostConstruct
    public void setKeyStore() {
        if (settings.getSignatureAlgorithm().isHmac()) {
            keyHolder = new KeyHolder(settings.getTokenSigningKey().getBytes(), null, null);
        } else if (settings.getSignatureAlgorithm().isRsa()) {
            KeyPair rsaKey = readKeyRSA();
            keyHolder = new KeyHolder(null, rsaKey.getPublic(), rsaKey.getPrivate());
        } else if (settings.getSignatureAlgorithm().isEllipticCurve()) {
            KeyPair ecKey = readKeyEC();
            keyHolder = new KeyHolder(null, ecKey.getPublic(), ecKey.getPrivate());
        }
    }


    private KeyPair readKeyRSA() {
        try {
            ClassLoader cl = Thread.currentThread().getContextClassLoader();
            InputStream in = cl.getResourceAsStream("sample-jwt.p12");
            KeyStore keystore = KeyStore.getInstance("pkcs12");
            keystore.load(in, "changeit".toCharArray());
            String alias = "sample-jwt";
            Key key = keystore.getKey(alias, "changeit".toCharArray());
            Certificate certificate = keystore.getCertificate(alias);
            return new KeyPair(certificate.getPublicKey(), (PrivateKey) key);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private KeyPair readKeyEC() {
        try {
            Security.addProvider(new BouncyCastleProvider());
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime192v1");
            KeyPairGenerator g = (KeyPairGenerator) KeyPairGenerator.getInstance("ECDSA", "BC");
            g.initialize(ecSpec, new SecureRandom());
            return g.generateKeyPair();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }

    }

    @Data
    @AllArgsConstructor
    private class KeyHolder {
        private byte[] secret;
        private PublicKey publicKey;
        private PrivateKey privateKey;
    }
}
