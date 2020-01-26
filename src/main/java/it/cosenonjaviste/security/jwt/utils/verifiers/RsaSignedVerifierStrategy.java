package it.cosenonjaviste.security.jwt.utils.verifiers;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;

class RsaSignedVerifierStrategy implements VerifierStrategy {

    private RSAKeyProvider keyProvider;

    RsaSignedVerifierStrategy(RSAKeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    @Override
    public Algorithm verify(DecodedJWT decodedJWT) {
        Algorithm algorithm = getAlgorithmInstanceFrom(decodedJWT.getAlgorithm());
        JWT.require(algorithm).build().verify(decodedJWT);
        return algorithm;
    }

    private Algorithm getAlgorithmInstanceFrom(String algorithm) {
        switch (algorithm) {
            case "RS256":
                return Algorithm.RSA256(keyProvider);
            case "RS384":
                return Algorithm.RSA384(keyProvider);
            case "RS512":
                return Algorithm.RSA512(keyProvider);
            default:
                throw new JWTVerificationException("With a keystore, only RSA algorithms are supported");
        }
    }
}
