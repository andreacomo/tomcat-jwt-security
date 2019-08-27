package it.cosenonjaviste.security.jwt.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import java.nio.file.attribute.UserPrincipal;
import java.util.List;

/**
 * Helper class for simplifying token verification procedure.
 * 
 * This class provides convenience methods to access <tt>userId</tt> and <tt>roles</tt> decodedJWT values.
 * If not present, an {@link IllegalStateException} is thrown
 * 
 * These values are mandatory in order to create {@link UserPrincipal} for each request
 * 
 * @author acomo
 *
 */
public class JwtTokenVerifier {
	
	private static final Log LOG = LogFactory.getLog(JwtTokenVerifier.class);
	
	private JWTVerifier verifier;

	private DecodedJWT decodedJWT;

	private Algorithm algorithm;

	private JwtTokenVerifier() {

	}
	
	/**
	 * Creates a new instance of {@link JwtTokenVerifier} class, using HMAC256 algorithm
	 * 
	 * @param secret secret phrase
	 * 
	 * @return a new instance of {@link JwtTokenVerifier} class
	 */
	public static JwtTokenVerifier create(String secret) {
		return create(Algorithm.HMAC256(secret));
	}

	/**
	 * Creates a new instance of {@link JwtTokenVerifier} class
	 *
	 * @param algorithm defines algorithm type to use with proper secret (already set)
	 *
	 * @return a new instance of {@link JwtTokenVerifier} class
	 */
	public static JwtTokenVerifier create(Algorithm algorithm) {
		JwtTokenVerifier tokenVerifier = new JwtTokenVerifier();
		tokenVerifier.verifier = JWT.require(algorithm).build();
		tokenVerifier.algorithm = algorithm;

		return tokenVerifier;
	}

	/**
	 * Verify provided token delegating verification logic to {@link JWTVerifier#verify(String)}
	 * 
	 * @param token JWT token
	 * 
	 * @return verification status
	 */
	public boolean verify(String token) {
		try {
			decodedJWT = this.verifier.verify(token);
			return decodedJWT != null;
		} catch (JWTVerificationException e) {
			LOG.info("Unable to verify token, caused by: " + e.getMessage(), e);
			return false;
		}
	}

	/**
	 * Verify provided token delegating verification logic to {@link JWTVerifier#verify(String)}
	 *
	 * @param token JWT token
	 *
	 * @return verification status
	 * @throws JWTVerificationException if validation fails
	 */
	public void verifyOrThrow(String token) {
		decodedJWT = this.verifier.verify(token);
	}

	/**
	 * Convenience method to retrieve <tt>userId</tt> value from token claim
	 * 
	 * @return <tt>userId</tt> value
	 */
	public String getUserId() {
		Preconditions.checkState(this.decodedJWT != null, "Please call verify method first!");
		return this.decodedJWT.getClaim(JwtConstants.USER_ID).asString();
	}
	
	/**
	 * Convenience method to retrieve <tt>roles</tt> value from token claim
	 * 
	 * @return <tt>roles</tt> value collection
	 */
	public List<String> getRoles() {
		Preconditions.checkState(this.decodedJWT != null, "Please call verify method first!");
		return this.decodedJWT.getClaim(JwtConstants.ROLES).asList(String.class);
	}
	
	/**
	 * Return validated decodedJWT
	 * 
	 * @return DecodedJWT instance
	 */
	public DecodedJWT getDecodedJWT() {
		Preconditions.checkState(this.decodedJWT != null, "Please call verify method first!");
		return this.decodedJWT;
	}

	Algorithm getAlgorithm() {
		return algorithm;
	}
}
