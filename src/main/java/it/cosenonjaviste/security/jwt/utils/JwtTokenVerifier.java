package it.cosenonjaviste.security.jwt.utils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.List;
import java.util.Map;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.internal.org.apache.commons.codec.binary.Base64;

public class JwtTokenVerifier {
	
	private static final Log LOG = LogFactory.getLog(JwtTokenVerifier.class);
	
	private JWTVerifier verifier;

	private Map<String, Object> claims;

	private JwtTokenVerifier() {

	}
	
	public static JwtTokenVerifier create(String secret, boolean isBase64) {
		JwtTokenVerifier tokenVerifier = new JwtTokenVerifier();
		if (isBase64) {
			tokenVerifier.verifier = new JWTVerifier(secret); 
		} else {
			tokenVerifier.verifier = new JWTVerifier(Base64.encodeBase64String(secret.getBytes(StandardCharsets.UTF_8)));
		}
		
		return tokenVerifier;
	}
	
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
	
	public String getUserId() {
		if (this.claims != null) {
			return (String) this.claims.get(JwtConstants.USER_ID);
		} else {
			throw new IllegalStateException("Please call verify method first!");
		}
	}
	
	@SuppressWarnings("unchecked")
	public List<String> getRoles() {
		if (this.claims != null) {
			return (List<String>) this.claims.get(JwtConstants.ROLES);
		} else {
			throw new IllegalStateException("Please call verify method first!");
		}
	}
}
