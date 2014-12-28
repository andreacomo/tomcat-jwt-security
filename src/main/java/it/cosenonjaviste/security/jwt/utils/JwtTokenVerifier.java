package it.cosenonjaviste.security.jwt.utils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.attribute.UserPrincipal;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.List;
import java.util.Map;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.internal.org.apache.commons.codec.binary.Base64;

/**
 * Helper class for simplifying token verification procedure.
 * 
 * This class provides convenience methods to access <tt>userId</tt> and <tt>roles</tt> claims values.
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

	private Map<String, Object> claims;

	private JwtTokenVerifier() {

	}
	
	/**
	 * Creates a new instance of {@link JwtTokenVerifier} class
	 * 
	 * @param secret secret phrase
	 * @param isBase64 is secret phrase base64 encoded?
	 * 
	 * @return a new instance of {@link JwtTokenVerifier} class
	 */
	public static JwtTokenVerifier create(String secret, boolean isBase64) {
		JwtTokenVerifier tokenVerifier = new JwtTokenVerifier();
		if (isBase64) {
			tokenVerifier.verifier = new JWTVerifier(secret); 
		} else {
			tokenVerifier.verifier = new JWTVerifier(Base64.encodeBase64String(secret.getBytes(StandardCharsets.UTF_8)));
		}
		
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
			claims = this.verifier.verify(token);
			return claims != null;
		} catch (InvalidKeyException | SignatureException
				| IllegalStateException e) {
			LOG.info("Invalid token, caused by: " + e.getMessage(), e);
			return false;

		} catch (NoSuchAlgorithmException | IOException e) {
			LOG.info("Unable to parse token, caused by: " + e.getMessage(), e);
			return false;
		}
	}
	
	/**
	 * Convenience method to retrieve <tt>userId</tt> value from token claim
	 * 
	 * @return <tt>userId</tt> value
	 * 
	 * @throws IllegalStateException if claims do not contain <tt>userId</tt> key
	 */
	public String getUserId() {
		if (this.claims != null) {
			return (String) this.claims.get(JwtConstants.USER_ID);
		} else {
			throw new IllegalStateException("Please call verify method first!");
		}
	}
	
	/**
	 * Convenience method to retrieve <tt>roles</tt> value from token claim
	 * 
	 * @return <tt>roles</tt> value collection
	 * 
	 * @throws IllegalStateException if claims do not contain <tt>roles</tt> key
	 */
	@SuppressWarnings("unchecked")
	public List<String> getRoles() {
		if (this.claims != null) {
			return (List<String>) this.claims.get(JwtConstants.ROLES);
		} else {
			throw new IllegalStateException("Please call verify method first!");
		}
	}
}
