package it.cosenonjaviste.security.jwt.utils.verifiers;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

/**
 * Verify tokens signed with HMAC.
 * <br>
 *
 * This verification strategy requires the secret the token was signed with.
 * <br>
 *
 * Supported algorithms are:
 * <ul>
 *     <li>HmacSHA256 (HS256)</li>
 *     <li>HmacSHA384 (HS384)</li>
 *     <li>HmacSHA512 (HS512)</li>
 * </ul>
 *
 * @author acomo
 */
class HmacSignedVerifierStrategy implements VerifierStrategy {

    private String secret;

    HmacSignedVerifierStrategy(String secret) {
        this.secret = secret;
    }

    @Override
    public Algorithm verify(DecodedJWT decodedJWT) {
        Algorithm algorithm = getAlgorithmInstanceFrom(decodedJWT.getAlgorithm());
        JWT.require(algorithm).build().verify(decodedJWT);
        return algorithm;
    }

    private Algorithm getAlgorithmInstanceFrom(String algorithm) {
        switch (algorithm) {
            case "HS256":
                return Algorithm.HMAC256(secret);
            case "HS384":
                return Algorithm.HMAC384(secret);
            case "HS512":
                return Algorithm.HMAC512(secret);
            default:
                throw new JWTVerificationException("With secret text, only HMAC algorithms are supported");
        }
    }
}
