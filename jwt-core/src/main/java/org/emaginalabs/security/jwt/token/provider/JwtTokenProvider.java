package org.emaginalabs.security.jwt.token.provider;


import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.emaginalabs.security.jwt.claims.JwtMap;
import org.emaginalabs.security.jwt.config.JwtSettings;
import org.emaginalabs.security.jwt.exceptions.InvalidJWTException;
import org.emaginalabs.security.jwt.token.model.AccessJwtToken;
import org.emaginalabs.security.jwt.token.model.JwtToken;
import org.joda.time.LocalDateTime;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

import javax.annotation.PostConstruct;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Class that manipulates with Json Web Tokens
 * Responsible for generating and parsing tokens jwt. also offers utilities on information to recover from a token
 */

@Slf4j
@RequiredArgsConstructor
public class JwtTokenProvider implements TokenProvider {

    public static final String TOKEN_PREFIX = "Bearer";            // the prefix of the token in the http header
    public static final String AUTHENTICATION_HEADER_NAME = "Authorization";    // the http header containing the prefix + the token
    private static final String ROLE_CLAIMS = "authorities";

    @Value("${spring.application.name:unknow-application}")
    private String appName;

    private final JwtSettings settings;

    @Autowired(required = false)
    private JwtMap customClaims;

    private KeyHolder keyHolderSignature;

    private KeyHolder keyHolderEncryption;

    /**
     * Creates token based on authentication detxails
     *
     * @param authentication Authentication
     * @return The generated token.
     */
    @SuppressWarnings("unchecked")
    @Override
    public JwtToken createToken(final Authentication authentication) {
        Assert.hasText(authentication.getName(), "Cannot create JWT Token without username");

        //TODO ver si se define clase encargada de dar la fecha
        LocalDateTime currentTime = LocalDateTime.now();

        JWTClaimsSet.Builder jwtClaimsSet = new JWTClaimsSet.Builder()
                .issuer(appName)
                .subject(authentication.getName())
                .issueTime(currentTime.toDate())
                .expirationTime(currentTime.plusMinutes(settings.getRefreshTokenExpTime()).toDate())
                .claim(ROLE_CLAIMS, getAuthoritiesStr((List<GrantedAuthority>) authentication.getAuthorities()))
                .claim("custom-claims", "test");

        if (customClaims != null) {
            log.debug("including custom claims defined by the bean {0}", customClaims.getClass().getName());
            for (Map.Entry<String, Object> entry : customClaims.entrySet()) {
                jwtClaimsSet.claim(entry.getKey(), entry.getValue());
            }

        }
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(settings.getSignatureAlgorithm()), jwtClaimsSet.build());
        try {
            //Determinate signed algorithm
            JWSSigner signer = keyHolderSignature.getSecret() != null ? new MACSigner(keyHolderSignature.getSecret()) : new RSASSASigner(keyHolderSignature.getPrivateKey());
            //Determinate encryption algorithm
            JWEEncrypter jweEncrypter = keyHolderEncryption.getSecret() != null ? new DirectEncrypter(keyHolderEncryption.getSecret()) : (new RSAEncrypter((RSAPublicKey) keyHolderEncryption.getPublicKey()));
            //sign
            signedJWT.sign(signer);
            String token;
            //custom claims
            if (!settings.isEncryptation()) {
                token = signedJWT.serialize();
            } else {
                JWEObject jweObject = new JWEObject(
                        new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
                                .contentType("JWT") // required to indicate nested JWT
                                .build(),
                        new Payload(signedJWT));

                jweObject.encrypt(jweEncrypter);


                // Serialise to JWE compact form
                token = jweObject.serialize();
            }
            log.debug("Access token created: {)", token);
            return new AccessJwtToken(token, signedJWT.getJWTClaimsSet());
        } catch (Exception e) {
            log.error("Error creating token", e);
            throw new InvalidJWTException(e.getMessage(), e);
        }

    }


    public SignedJWT validateToken(String token) {
        try {
            SignedJWT signedJWT;
            if (settings.isEncryptation()) {
                JWEObject jweObject = JWEObject.parse(token.replace(TOKEN_PREFIX, ""));
                // Decrypt with private key
                jweObject.decrypt(new RSADecrypter(keyHolderEncryption.getPrivateKey()));

                // Extract payload
                signedJWT = jweObject.getPayload().toSignedJWT();

            } else {
                signedJWT = SignedJWT.parse(token.replace(TOKEN_PREFIX, ""));
            }

            if (settings.isValidateSigned()) {
                JWSVerifier verifier = keyHolderSignature.getSecret() != null ? new MACVerifier(settings.getTokenSigningKey()) :
                        new RSASSAVerifier((RSAPublicKey) keyHolderSignature.getPublicKey());
                if (signedJWT.verify(verifier)) {
                    DefaultJWTClaimsVerifier jwtClaimsVerifier = new DefaultJWTClaimsVerifier();
                    jwtClaimsVerifier.verify(signedJWT.getJWTClaimsSet());
                    return signedJWT;
                }
            }
            return signedJWT;

        } catch (BadJWTException badJWTException) {
            log.error(badJWTException.getMessage(), badJWTException);
            throw new InvalidJWTException(badJWTException.getMessage(), badJWTException);
        } catch (Exception ex) {
            log.error("Invalid JWT Token: " + ex.getMessage(), ex);
            throw new InvalidJWTException("Invalid jwt token: :" + ex.getMessage(), ex);

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
            SignedJWT signedJWT = validateToken(token);
            try {
                String user = parseUsername(signedJWT.getJWTClaimsSet());
                List<GrantedAuthority> authorities = parseRoles(signedJWT.getJWTClaimsSet());
                UserDetails userDetails = createUser2Token(signedJWT.getJWTClaimsSet());

                //TODO si se han incluido algunos otros claims no se setean en el objeto de seguridad
                if (user != null) {
                    return new UsernamePasswordAuthenticationToken(userDetails, null, authorities);
                }
            } catch (ParseException ex) {
                log.error("Error to parse token", ex);
            }
        }

        return null;
    }

    private UserDetails createUser2Token(JWTClaimsSet jwtClaimsSet) {

        JwtUserDetailsImpl.Essence user = new JwtUserDetailsImpl.Essence();
        user.setAuthorities(parseRoles(jwtClaimsSet));
        user.setUsername(parseUsername(jwtClaimsSet));
        user.setClaims(jwtClaimsSet.getClaims());
        return user.createUserDetails();
    }

    /**
     * Parse a token and extract the subject (username).
     *
     * @param claims claims jwt.
     * @return The subject (username) of the token.
     */
    public String parseUsername(JWTClaimsSet claims) {

        return claims
                .getSubject();

    }


    @SuppressWarnings("unchecked")
    public List<GrantedAuthority> parseRoles(JWTClaimsSet claims) {

        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        List<String> roles = (List<String>) claims
                .getClaim((ROLE_CLAIMS));

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


    public JWTClaimsSet getJwtClaims(final String token) {

        SignedJWT jwtParser = null;
        try {
            jwtParser = SignedJWT.parse(token);
            return jwtParser.getJWTClaimsSet();

        } catch (ParseException e) {
            log.error("Invalid token", e);
        }

        return null;
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
                .getClaim(claim);
    }


    @PostConstruct
    public void setKeyStore() {
        log.info("JWT security with next configuration: " +
                        "Signature algorithm: {}, " +
                        "active encryption : {} with encryption algorithm : {} " +
                        "token response:  [{}], token expiration time (min) : {}, url login path : {}, secure path : {} ",
                settings.getSignatureAlgorithmStr(), settings.isEncryptation(), settings.getEncryptationAlgorithmStr(),
                settings.getTokenResponse(), settings.getTokenExpirationTime(), settings.getLoginPath(), settings.getSecurePath());
        loadKeyStoreSignature();
        loadKeyStoreEncryptation();

    }

    private void loadKeyStoreSignature() {
        if (settings.getSignatureAlgorithm().getName().startsWith("HS")) {
            keyHolderSignature = new KeyHolder(settings.getTokenSigningKey().getBytes(), null, null);
        } else if (settings.getSignatureAlgorithm().getName().startsWith("RS")) {
            KeyPair rsaKey = readKeyRSA("sample-jws.p12", "changeit", "sample-jws");
            keyHolderSignature = new KeyHolder(null, rsaKey.getPublic(), rsaKey.getPrivate());
        } else if (settings.getSignatureAlgorithm().getName().startsWith("ES")) {
            KeyPair ecKey = readJWSKeyEC();
            keyHolderSignature = new KeyHolder(null, ecKey.getPublic(), ecKey.getPrivate());
        }
    }

    private void loadKeyStoreEncryptation() {
        if (settings.getEncryptationAlgorithm().getName().startsWith("AES")) {
            keyHolderEncryption = new KeyHolder(settings.getTokenSigningKey().getBytes(), null, null);
        } else if (settings.getEncryptationAlgorithm().getName().startsWith("RS")) {
            KeyPair rsaKey = readKeyRSA("sample-jwe.p12", "changeit", "sample-jwe");
            keyHolderEncryption = new KeyHolder(null, rsaKey.getPublic(), rsaKey.getPrivate());
        }
    }

    private KeyPair readKeyRSA(String nameCertificate, String pass, String alias) {
        try {
            ClassLoader cl = Thread.currentThread().getContextClassLoader();
            InputStream in = cl.getResourceAsStream(nameCertificate);
            KeyStore keystore = KeyStore.getInstance("pkcs12");
            keystore.load(in, pass.toCharArray());
            Key key = keystore.getKey(alias, pass.toCharArray());
            Certificate certificate = keystore.getCertificate(alias);
            return new KeyPair(certificate.getPublicKey(), (PrivateKey) key);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private KeyPair readJWSKeyEC() {
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
