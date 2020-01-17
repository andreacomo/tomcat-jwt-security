package it.cosenonjaviste.security.jwt.utils.verifiers;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

class HmacSecretTextVerifierStrategy implements VerifierStrategy {

    private String secret;

    HmacSecretTextVerifierStrategy(String secret) {
        this.secret = secret;
    }

    @Override
    public Algorithm verify(DecodedJWT decodedJWT) {
        Algorithm algorithm = getAlgorithmInstanceFrom(decodedJWT.getAlgorithm());
        algorithm.verify(decodedJWT);
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
