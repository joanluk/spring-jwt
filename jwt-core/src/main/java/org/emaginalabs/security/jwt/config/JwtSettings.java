package org.emaginalabs.security.jwt.config;

import io.jsonwebtoken.SignatureAlgorithm;
import lombok.Data;
import org.springframework.beans.factory.annotation.Value;


@Data
public class JwtSettings {

    /**
     * Token will expire after this time.
     */
    @Value("${app.security.jwt.token.expiration.time}")
    private Integer tokenExpirationTime = 15;

    @Value("${app.security.jwt.path.login:/login}")
    private String loginPath;

    @Value("${app.security.jwt.path.secure:/**}")
    private String securePath;

    @Value("${app.security.jwt.paths.allow}")
    private String pathAllow;
    /**
     * Token issuer.
     */
    @Value("${app.security.jwt.token.issuer}")
    private String tokenIssuer = "user";

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


    @Value("${app.security.jwt.token.response}")
    private String tokenResponse;

    @Value("${app.security.jwt.token.compresion}")
    private boolean compresion;

    public SignatureAlgorithm getSignatureAlgorithm() {
        return SignatureAlgorithm.forName(signatureAlgorithmStr);
    }

}
