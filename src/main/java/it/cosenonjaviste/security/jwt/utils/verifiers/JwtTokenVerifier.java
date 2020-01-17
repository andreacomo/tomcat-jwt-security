package it.cosenonjaviste.security.jwt.utils.verifiers;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import it.cosenonjaviste.security.jwt.model.JwtAdapter;

import java.nio.file.attribute.UserPrincipal;

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
	
	private VerifierStrategy verifierStrategy;

	private JwtTokenVerifier() {

	}
	
	/**
	 * Creates a new instance of {@link JwtTokenVerifier} class
	 * 
	 * @param secret secret phrase
	 * 
	 * @return a new instance of {@link JwtTokenVerifier} class
	 */
	public static JwtTokenVerifier create(String secret) {
		JwtTokenVerifier tokenVerifier = new JwtTokenVerifier();
		tokenVerifier.verifierStrategy = new HmacSecretTextVerifierStrategy(secret);
		return tokenVerifier;
	}

	/**
	 * Verify provided token delegating verification logic to proper strategy of {@link VerifierStrategy}
	 *
	 * @param token JWT token
	 *
	 * @throws JWTVerificationException if validation fails
	 *
	 * @return {@link JwtAdapter}
	 */
	public JwtAdapter verify(String token) {
		DecodedJWT decodedJWT = JWT.decode(token);
		Algorithm algorithm = verifierStrategy.verify(decodedJWT);
		return new JwtAdapter(algorithm, decodedJWT);
	}
}
