package it.cosenonjaviste.security.jwt.utils;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import com.auth0.jwt.Algorithm;
import com.auth0.jwt.JWTSigner;
import com.auth0.jwt.JWTSigner.Options;

/**
 * Builder class for simplifying JWT token creation.
 * 
 * <tt>userId</tt> and <tt>roles</tt> values are mandatory.
 * 
 * @author acomo
 *
 */
public class JwtTokenBuilder {
	
	private static final String NOT_BEFORE = "nbf";

	private static final String JWT_ID = "jti";

	private static final String EXPIRE = "exp";

	private static final String ISSUED_AT = "iat";

	private JWTSigner signer;
	
	private Map<String, Object> claims = new HashMap<>();

	private Options options = new Options();
	
	private JwtTokenBuilder() {
		
	}
	
	/**
	 * Creates a new {@link JwtTokenBuilder} instance
	 * 
	 * @param secret secret phrase
	 * 
	 * @return a new {@link JwtTokenBuilder} instance
	 */
	public static JwtTokenBuilder create(String secret) {
		JwtTokenBuilder builder = new JwtTokenBuilder();
		builder.signer = new JWTSigner(secret); 
		builder.options.setIssuedAt(true);
		
		return builder;
	}
	
	/**
	 * Creates a {@link JwtTokenBuilder} instance from token and secret.
	 * <br >
	 * Token will be <strong>validated</strong> before parsing.
	 * <br >
	 * Token <strong>must</strong> contains "<em>iat</em>" param in order to restore builder status
	 * <br >
	 * <br >
	 * Rebuilding this token has side effect:
	 * <ul>
	 * <li>if "<em>jti</em>" param is present, will be overwritten</li> 
	 * <li>if "<em>exp</em>" param is present, expire time will be recalculated starting from current timestamp</li> 
	 * <li>if "<em>nbf</em>" param is present, its value will be recalculated starting from current timestamp</li> 
	 * </ul>
	 * 
	 * @param token
	 * @param secret
	 * @return
	 */
	public static JwtTokenBuilder from(String token, String secret) {
		JwtTokenVerifier verifier = JwtTokenVerifier.create(secret);
		verifier.verify(token);
		return from(verifier, secret);
	}

	/**
	 * Creates a {@link JwtTokenBuilder} instance from token and secret.
	 * <br >
	 * Token <strong>must</strong> contains "<em>iat</em>" param in order to restore builder status
	 * <br >
	 * Use this method if you want to edit current token: if "<em>jti</em>" param is present, will be overwritten 
	 * <br >
	 * Token <strong>must</strong> be verified before calling this method
	 * <br >
	 * <br >
	 * Rebuilding this token has side effect:
	 * <ul>
	 * <li>if "<em>jti</em>" param is present, will be overwritten</li> 
	 * <li>if "<em>exp</em>" param is present, expire time will be recalculated starting from current timestamp</li> 
	 * <li>if "<em>nbf</em>" param is present, its value will be recalculated starting from current timestamp</li> 
	 * </ul>
	 * 
	 * @param verifier
	 * @param secret
	 * @return
	 * 
	 * @throws IllegalStateException if token is not verified by provided verifier
	 */
	public static JwtTokenBuilder from(JwtTokenVerifier verifier, String secret) {
		JwtTokenBuilder builder = create(secret);
		Map<String, Object> verifiedClaims = verifier.getClaims();
		restoreInternalStatus(builder, verifiedClaims);
		return builder;
	}

	/**
	 * Creates a {@link JwtTokenBuilder} instance from token and secret.
	 * <br >
	 * Token will be <strong>validated</strong> before parsing.
	 * <br >
	 * Token <strong>must</strong> contains "<em>iat</em>" param in order to restore builder status
	 * <br >
	 * Use this method if you want to edit current token: if "<em>jti</em>" param is present, will be overwritten 
	 * <br >
	 * <br >
	 * Rebuilding this token has side effect:
	 * <ul>
	 * <li>if "<em>jti</em>" param is present, will be overwritten</li> 
	 * <li>if "<em>exp</em>" param is present, expire time will be recalculated starting from current timestamp</li> 
	 * <li>if "<em>nbf</em>" param is present, its value will be recalculated starting from current timestamp</li> 
	 * </ul>
	 * @param verifier
	 * @param token
	 * @param secret
	 * @return
	 * 
	 * @throws IllegalStateException if token is not verified by provided verifier
	 */
	public static JwtTokenBuilder from(JwtTokenVerifier verifier, String token, String secret) {
		verifier.verify(token);
		return from(verifier, secret);
	}
	
	private static void restoreInternalStatus(JwtTokenBuilder builder, Map<String, Object> verifiedClaims) {
		if (verifiedClaims.containsKey(ISSUED_AT)) {
			int issuedAt = (int) verifiedClaims.remove(ISSUED_AT);
			if (verifiedClaims.containsKey(EXPIRE)) {
				int expire = (int) verifiedClaims.remove(EXPIRE) - issuedAt;
				builder.options.setExpirySeconds(expire);
			}
			if (verifiedClaims.containsKey(NOT_BEFORE)) {
				int notBefore = issuedAt - (int) verifiedClaims.remove(NOT_BEFORE);
				builder.options.setNotValidBeforeLeeway(notBefore);
			}
			if (verifiedClaims.containsKey(JWT_ID)) {
				verifiedClaims.remove(JWT_ID);
				builder.options.setJwtId(true);
			}
			builder.claims.putAll(verifiedClaims);
		} else {
			throw new IllegalStateException("Missing 'iat' value. Unable to restore builder status");
		}
	}

	/**
	 * Add <tt>userId</tt> claim to JWT body
	 * 
	 * @param name realm username
	 * 
	 * @return {@link JwtTokenBuilder}
	 */
	public JwtTokenBuilder userId(String name) {
		return claimEntry(JwtConstants.USER_ID, name);
	}
	
	/**
	 * Add <tt>roles</tt> claim to JWT body
	 * 
	 * @param roles
	 * 
	 * @return {@link JwtTokenBuilder}
	 */
	public JwtTokenBuilder roles(Collection<String> roles) {
		return claimEntry(JwtConstants.ROLES, roles);
	}
	
	/**
	 * Add a custom claim to JWT body
	 * 
	 * @param key
	 * @param value
	 * 
	 * @return {@link JwtTokenBuilder}
	 */
	public JwtTokenBuilder claimEntry(String key, Object value) {
		claims.put(key, value);
		return this;
	}
	
	/**
	 * Add JWT claim <tt>exp</tt> to current timestamp + seconds.
	 * 
	 * @param seconds
	 * 
	 * @return {@link JwtTokenBuilder}
	 */
	public JwtTokenBuilder expirySecs(int seconds) {
		options.setExpirySeconds(seconds);
		return this;
	}
	
	/**
	 * Specify algorithm to sign JWT with. Default is HS256.
	 * 
	 * @param algorithm
	 * 
	 * @return {@link JwtTokenBuilder}
	 */
	public JwtTokenBuilder algorithm(Algorithm algorithm) {
		options.setAlgorithm(algorithm);
		return this;
	}
	
	/**
	 * Should JWT claim <tt>iat</tt> be added?
	 * Value will be set to current timestamp
	 * 
	 * @param issuedAt
	 * 
	 * @return {@link JwtTokenBuilder}
	 */
	public JwtTokenBuilder issuedEntry(boolean issuedAt) {
		options.setIssuedAt(issuedAt);
		return this;
	}
	
	/**
	 * Should JWT claim <tt>jti</tt> be added?
	 * Value will be set to a pseudo random unique value (UUID)
	 * 
	 * @param jwtId
	 * 
	 * @return {@link JwtTokenBuilder}
	 */
	public JwtTokenBuilder generateJwtId(boolean jwtId) {
		options.setJwtId(jwtId);
		return this;
	}
	
	/**
	 * Add JWT claim <tt>nbf</tt> to current timestamp - notValidBeforeLeeway
	 * 
	 * @param notValidBeforeLeeway
	 * 
	 * @return {@link JwtTokenBuilder}
	 */
	public JwtTokenBuilder notValidBeforeLeeway(int notValidBeforeLeeway) {
		options.setNotValidBeforeLeeway(notValidBeforeLeeway);
		return this;
	}
	
	/**
	 * Create a new JWT token
	 * 
	 * @return JWT token
	 * 
	 * @throws IllegalStateException if <tt>userId</tt> and <tt>roles</tt> are not provided
	 */
	public String build() {
		if (claims.containsKey(JwtConstants.USER_ID) && claims.containsKey(JwtConstants.ROLES)) {
			return signer.sign(claims, options);			
		} else {
			throw new IllegalStateException("userId and roles claims must be added!");
		}
	}
}
