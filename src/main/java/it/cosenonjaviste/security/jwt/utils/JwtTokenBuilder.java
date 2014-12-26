package it.cosenonjaviste.security.jwt.utils;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import com.auth0.jwt.Algorithm;
import com.auth0.jwt.JWTSigner;
import com.auth0.jwt.JWTSigner.Options;

public class JwtTokenBuilder {
	
	private JWTSigner signer;
	
	private Map<String, Object> claims = new HashMap<>();

	private Options options = new Options();
	
	private JwtTokenBuilder() {
		
	}
	
	public static JwtTokenBuilder create(String secret) {
		JwtTokenBuilder builder = new JwtTokenBuilder();
		builder.signer = new JWTSigner(secret); 
		
		return builder;
	}
	
	public JwtTokenBuilder userId(String name) {
		return claimEntry(JwtConstants.USER_ID, name);
	}
	
	public JwtTokenBuilder roles(Collection<String> roles) {
		return claimEntry(JwtConstants.ROLES, roles);
	}
	
	public JwtTokenBuilder claimEntry(String key, Object value) {
		claims.put(key, value);
		return this;
	}
	
	public JwtTokenBuilder expirySecs(int seconds) {
		options.setExpirySeconds(seconds);
		return this;
	}
	
	public JwtTokenBuilder algorithm(Algorithm algorithm) {
		options.setAlgorithm(algorithm);
		return this;
	}
	
	public JwtTokenBuilder issuedEntry(boolean issuedAt) {
		options.setIssuedAt(issuedAt);
		return this;
	}
	
	public JwtTokenBuilder generateJwtId(boolean jwtId) {
		options.setJwtId(jwtId);
		return this;
	}
	
	public JwtTokenBuilder notValidBeforeLeeway(int notValidBeforeLeeway) {
		options.setNotValidBeforeLeeway(notValidBeforeLeeway);
		return this;
	}
	
	public String build() {
		return signer.sign(claims, options);
	}
}
