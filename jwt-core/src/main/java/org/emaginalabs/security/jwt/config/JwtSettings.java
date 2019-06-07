package org.emaginalabs.security.jwt.config;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;


@Data
@Slf4j
public class JwtSettings {

    /**
     * Token will expire after this time.
     */
    @Value("${app.security.jwt.token.expiration.time}")
    private Integer tokenExpirationTime = 15;

    @Value("${app.security.jwt.path.login:/api/login}")
    private String loginPath;

    @Value("${app.security.jwt.path.secure:/**}")
    private String securePath;

    @Value("${app.security.jwt.paths.allow}")
    private String pathAllow;
    /**
     * Token issuer.
     */
    @Value("${app.security.jwt.token.issuer}")
    private String tokenIssuer = "gaia-app";

    /**
     * Key is used to sign token
     */
    @Value("${app.security.jwt.token.sign.key}")
    private String tokenSigningKey = "ThisIsASecret";

    /**
     * Token can be refreshed during this timeframe.
     */
    @Value("${app.security.jwt.token.refresh.time}")
    private Integer refreshTokenExpTime = 15;


    @Value("${app.security.jwt.paths.allow}")
    private String authenticationUrl;

    @Value("${app.security.jwt.signature.algorithm}")
    private String signatureAlgorithmStr;

    @Value("${app.security.jwt.encryptation.algorithm}")
    private String encryptationAlgorithmStr;


    @Value("${app.security.jwt.encryptation.active:false}")
    private boolean encryptation;

    @Value("${app.security.jwt.token.response}")
    private String tokenResponse;

    @Value("${app.security.jwt.token.compresion}")
    private boolean compresion;

    @Value("${app.security.jwt.signature.validate:true}")
    private boolean validateSigned;

    @Value("${app.security.jwt.login.enabled:false}")
    private boolean apiLoginEnabled;

    public JWSAlgorithm getSignatureAlgorithm() {
        return JWSAlgorithm.parse(signatureAlgorithmStr);
    }

    public JWEAlgorithm getEncryptationAlgorithm() {
        return JWEAlgorithm.parse(encryptationAlgorithmStr);
    }



}
