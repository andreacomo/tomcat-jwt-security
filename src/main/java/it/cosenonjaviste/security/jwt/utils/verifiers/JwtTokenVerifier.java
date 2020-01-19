package it.cosenonjaviste.security.jwt.utils.verifiers;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;
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

	private String customUserIdClaim;

	private String customRolesClaim;

	private JwtTokenVerifier() {

	}
	
	/**
	 * Creates a new instance of {@link JwtTokenVerifier} class for HMAC and secret text sign
	 * 
	 * @param secret secret phrase
	 * 
	 * @return a new instance of {@link JwtTokenVerifier} class
	 */
	public static JwtTokenVerifier create(String secret) {
		JwtTokenVerifier tokenVerifier = new JwtTokenVerifier();
		tokenVerifier.verifierStrategy = new HmacSignedVerifierStrategy(secret);
		return tokenVerifier;
	}

	/**
	 * Creates a new instance of {@link JwtTokenVerifier} class for HMAC and secret text sign
	 *
	 * @param secret secret phrase
	 * @param customUserIdClaim claim to use for identifying user id
	 * @param customRolesClaim claim to use fot identifies user roles
	 *
	 * @return a new instance of {@link JwtTokenVerifier} class
	 */
	public static JwtTokenVerifier create(String secret, String customUserIdClaim, String customRolesClaim) {
		JwtTokenVerifier tokenVerifier = new JwtTokenVerifier();
		tokenVerifier.verifierStrategy = new HmacSignedVerifierStrategy(secret);
		tokenVerifier.customUserIdClaim = customUserIdClaim;
		tokenVerifier.customRolesClaim = customRolesClaim;
		return tokenVerifier;
	}

	/**
	 * Creates a new instance of {@link JwtTokenVerifier} class for RSA and certificate verification
	 *
	 * @param rsaKeyProvider key provider
	 *
	 * @return a new instance of {@link JwtTokenVerifier} class
	 */
	public static JwtTokenVerifier create(RSAKeyProvider rsaKeyProvider) {
		JwtTokenVerifier tokenVerifier = new JwtTokenVerifier();
		tokenVerifier.verifierStrategy = new RsaSignedVerifierStrategy(rsaKeyProvider);
		return tokenVerifier;
	}

	/**
	 * Creates a new instance of {@link JwtTokenVerifier} class for RSA and certificate verification
	 *
	 * @param rsaKeyProvider key provider
	 * @param customUserIdClaim claim to use for identifying user id
	 * @param customRolesClaim claim to use fot identifies user roles
	 *
	 * @return a new instance of {@link JwtTokenVerifier} class
	 */
	public static JwtTokenVerifier create(RSAKeyProvider rsaKeyProvider, String customUserIdClaim, String customRolesClaim) {
		JwtTokenVerifier tokenVerifier = new JwtTokenVerifier();
		tokenVerifier.verifierStrategy = new RsaSignedVerifierStrategy(rsaKeyProvider);
		tokenVerifier.customUserIdClaim = customUserIdClaim;
		tokenVerifier.customRolesClaim = customRolesClaim;
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
		return new JwtAdapter(algorithm, decodedJWT, customUserIdClaim, customRolesClaim);
	}
}
