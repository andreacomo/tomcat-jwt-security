package it.cosenonjaviste.security.jwt.utils.verifiers;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

interface VerifierStrategy {

    Algorithm verify(DecodedJWT token) throws SignatureVerificationException;
}
