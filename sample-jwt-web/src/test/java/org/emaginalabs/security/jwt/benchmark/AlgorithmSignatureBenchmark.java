package org.emaginalabs.security.jwt.benchmark;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.emaginalabs.security.jwt.exceptions.InvalidJWTException;

import java.io.InputStream;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

public class AlgorithmSignatureBenchmark implements Runnable {

    public static void main(String[] args) {
        new AlgorithmSignatureBenchmark().run();
    }

    public void run() {
        int count = 1000;
        KeyPair rsaKeySignature = readKeyRSA("sample-jws.p12", "changeit", "sample-jws");
        KeyPair rsaKeyEnctyption = readKeyRSA("sample-jwe.p12", "changeit", "sample-jwe");
        SecureRandom random = new SecureRandom();
        byte[] sharedSecret256 = new byte[32];
        byte[] sharedSecret384 = new byte[48];
        byte[] sharedSecret512 = new byte[64];

        random.nextBytes(sharedSecret256);
        random.nextBytes(sharedSecret384);
        random.nextBytes(sharedSecret512);
        KeyHolder secretKeyHolder256 = new KeyHolder(sharedSecret256, null, null);
        KeyHolder secretKeyHolder384 = new KeyHolder(sharedSecret384, null, null);
        KeyHolder secretKeyHolder512 = new KeyHolder(sharedSecret512, null, null);

        KeyHolder rsaKeyHolderSignature = new KeyHolder(null, rsaKeySignature.getPublic(), rsaKeySignature.getPrivate());

        // Generate an EC key pair
        KeyHolder ecKeyHolderP256 = null;
        KeyHolder ecKeyHolderP384 = null;
        KeyHolder ecKeyHolderP512 = null;
        try {
            ECKey ecJWKP256 = new ECKeyGenerator(Curve.P_256)
                    .keyID("123")
                    .generate();
            ECKey ecJWKP384 = new ECKeyGenerator(Curve.P_384)
                    .keyID("1234")
                    .generate();
            ECKey ecJWKP512 = new ECKeyGenerator(Curve.P_521)
                    .keyID("1235")
                    .generate();
            ecKeyHolderP256 = new KeyHolder(null, ecJWKP256.toPublicKey(), ecJWKP256.toPrivateKey());
            ecKeyHolderP384 = new KeyHolder(null, ecJWKP384.toPublicKey(), ecJWKP384.toPrivateKey());
            ecKeyHolderP512 = new KeyHolder(null, ecJWKP512.toPublicKey(), ecJWKP512.toPrivateKey());
        } catch (Exception ex) {
            throw new InvalidJWTException("Invalid generation key for EC algorithm", ex);
        }

        //encryption
        KeyHolder keyHolderEncryption = new KeyHolder(null, rsaKeyEnctyption.getPublic(), rsaKeyEnctyption.getPrivate());

//        for (String name : new String[]{"RS256", "RS384", "RS512"}) {
//            runAlg(JWSAlgorithm.parse(name), rsaKeyHolderSignature, keyHolderEncryption, count);
//        }
//        for (String name : new String[]{"HS256", "HS384", "HS512"}) {
//            JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse(name);
//            if (jwsAlgorithm.equals(JWSAlgorithm.HS256)) {
//                runAlg(JWSAlgorithm.parse(name), secretKeyHolder256, keyHolderEncryption, count);
//            } else if (jwsAlgorithm.equals(JWSAlgorithm.HS384)) {
//                runAlg(JWSAlgorithm.parse(name), secretKeyHolder384, keyHolderEncryption, count);
//            } else {
//                runAlg(JWSAlgorithm.parse(name), secretKeyHolder512, keyHolderEncryption, count);
//            }
//        }
        System.out.println("Following alg requires bouncycastle");
//        for (String name : new String[]{"ES256", "ES384", "ES512"}) {
//            if (name.equalsIgnoreCase("ES256")) {
//                runAlg(JWSAlgorithm.parse(name), ecKeyHolderP256, keyHolderEncryption, count);
//            } else if (name.equalsIgnoreCase("ES384")) {
//                runAlg(JWSAlgorithm.parse(name), ecKeyHolderP384, keyHolderEncryption, count);
//            } else {
//                runAlg(JWSAlgorithm.parse(name), ecKeyHolderP512, keyHolderEncryption, count);
//            }
//        }
        for (String name : new String[]{"PS256", "PS384", "PS512"}) {
            runAlg(JWSAlgorithm.parse(name), rsaKeyHolderSignature, keyHolderEncryption, count);
        }
    }

    private void runAlg(JWSAlgorithm alg, KeyHolder holderSignature, KeyHolder holderEncryption, int count) {
        try {
            String token = null;
            long t0;
            long t;
            BigDecimal avg;
            System.out.println("--------------------------------------------------------");
            System.out.println(alg + " (" + alg.getName() + ")");
            t0 = System.currentTimeMillis();
            for (int i = 0; i < count; i++) {
                token = generateToken(alg, holderSignature, holderEncryption);
            }
            t = System.currentTimeMillis() - t0;
            avg = new BigDecimal(t).divide(new BigDecimal(count), 5, RoundingMode.HALF_EVEN);
            System.out.println("  generate: " + t + "ms (" + avg + " ms avg)");
            t0 = System.currentTimeMillis();
            for (int i = 0; i < count; i++) {
                validateToken(token, alg, holderSignature, holderEncryption);
            }
            t = System.currentTimeMillis() - t0;
            avg = new BigDecimal(t).divide(new BigDecimal(count), 5, RoundingMode.HALF_EVEN);
            System.out.println("  validate: " + t + "ms (" + avg + " avg)");
        } catch (Exception ex) {
            ex.printStackTrace(System.out);
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


    private String generateToken(JWSAlgorithm alg, KeyHolder holder, KeyHolder keyHolderEncryption) {

        JWTClaimsSet.Builder jwtClaimsSet = new JWTClaimsSet.Builder()
                .audience("sample-jwt-core")
                .issueTime(Calendar.getInstance().getTime())
                .expirationTime(new Date(System.currentTimeMillis() + 6000000))
                .claim("appRoles", Arrays.asList("A", "B", "C"));
        try {
            JWSSigner signer = createJWSSigner(alg, holder);
            SignedJWT signedJWT = new SignedJWT(new JWSHeader(alg), jwtClaimsSet.build());
            signedJWT.sign(signer);
            JWEEncrypter jweEncrypter = keyHolderEncryption.getSecret() != null ? new DirectEncrypter(keyHolderEncryption.getSecret()) : (new RSAEncrypter((RSAPublicKey) keyHolderEncryption.getPublicKey()));

            JWEObject jweObject = new JWEObject(
                    new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
                            .contentType("JWT") // required to indicate nested JWT
                            .build(),
                    new Payload(signedJWT));

            jweObject.encrypt(jweEncrypter);

            return jweObject.serialize();

        } catch (Exception e) {
            System.out.println("Error creating token");
            throw new InvalidJWTException(e.getMessage(), e);
        }
    }

    private void validateToken(String token, JWSAlgorithm algorithm, KeyHolder holder, KeyHolder keyHolderEncryption) {
        try {

            //decrypt
            JWEObject jweObject = JWEObject.parse(token);
            // Decrypt with private key
            jweObject.decrypt(new RSADecrypter(keyHolderEncryption.getPrivateKey()));
            JWSVerifier verifier = createJWSVerifier(algorithm, holder);

            SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
            if (signedJWT.verify(verifier)) {
                DefaultJWTClaimsVerifier jwtClaimsVerifier = new DefaultJWTClaimsVerifier();
                jwtClaimsVerifier.verify(signedJWT.getJWTClaimsSet());
            }
        } catch (Exception e) {
            System.out.println("Error creating token");
            throw new InvalidJWTException(e.getMessage(), e);
        }
    }

    @Data
    @AllArgsConstructor
    private class KeyHolder {
        private byte[] secret;
        private PublicKey publicKey;
        private PrivateKey privateKey;
    }


    private JWSSigner createJWSSigner(JWSAlgorithm algorithm, KeyHolder holder) {
        try {
            if (algorithm.getName().startsWith("HS")) {
                return new MACSigner(holder.getSecret());
            } else if (algorithm.getName().startsWith("ES")) {

                return new ECDSASigner((ECPrivateKey) holder.privateKey);
            } else {
                return new RSASSASigner(holder.getPrivateKey());
            }
        } catch (KeyLengthException keyEx) {
            System.out.println("Error with secret pass size");
            throw new InvalidJWTException(keyEx.getMessage(), keyEx);
        } catch (JOSEException joseEx) {
            throw new InvalidJWTException(joseEx.getMessage(), joseEx);
        }

    }

    private JWSVerifier createJWSVerifier(JWSAlgorithm algorithm, KeyHolder holder) {
        try {
            if (algorithm.getName().startsWith("HS")) {
                return new MACVerifier(holder.getSecret());
            } else if (algorithm.getName().startsWith("ES")) {

                return new ECDSAVerifier((ECPublicKey) holder.getPublicKey());
            } else {
                return new RSASSAVerifier((RSAPublicKey) holder.getPublicKey());
            }
        } catch (KeyLengthException keyEx) {
            System.out.println("Error with secret pass size");
            throw new InvalidJWTException(keyEx.getMessage(), keyEx);
        } catch (JOSEException joseEx) {
            throw new InvalidJWTException(joseEx.getMessage(), joseEx);
        }
    }

}