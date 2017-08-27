package it.cosenonjaviste.security.jwt.utils;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.junit.Test;

import com.auth0.jwt.JWTVerifier;

public class JwtTokenBuilderTest {

	private static final String SECRET = "my secret";
	
	@Test
	public void shouldContains5Claims() throws Exception {
		String token = createToken();
		
		assertNotNull(token);
		
		JWTVerifier verifier = new JWTVerifier(SECRET);
		Map<String, Object> tokenObject = verifier.verify(token);
		
		assertNotNull(tokenObject);
		assertEquals(5, tokenObject.size());
		assertEquals(tokenObject.get(JwtConstants.USER_ID), "test");
		assertEquals(tokenObject.get(JwtConstants.ROLES), Arrays.asList("role1, role2"));
		
		long now = System.currentTimeMillis() / 1000L;
		long timeToExpire = ((int)tokenObject.get("exp")) - now;
		assertTrue(timeToExpire > 0);
		assertTrue(timeToExpire <= 10000);
		
		int issueTime = (int) tokenObject.get("iat");
		assertTrue(issueTime <= now);
	}

	@Test(expected=IllegalStateException.class)
	public void shouldBeEmptyAndInvalid() throws Exception {
		JwtTokenBuilder.create(SECRET).build();
	}
	
	@Test
	public void shouldParseJwtFromString() throws Exception {
		String token = createToken();
		
		assertNotNull(token);
		
		JwtTokenBuilder from = JwtTokenBuilder.from(token, SECRET);
		String token2 = from.expirySecs(20000).notValidBeforeLeeway(10000).build();
		
		int now = (int) (System.currentTimeMillis() / 1000L);
		JWTVerifier verifier = new JWTVerifier(SECRET);
		Map<String, Object> tokenObject = verifier.verify(token2);

		int exp = (int) tokenObject.get("exp");
		assertTrue(exp <= now + 20000);
		assertTrue(exp > now);

		int nbf = (int) tokenObject.get("nbf");
		assertTrue(nbf >= now - 10000);
		assertTrue(nbf < now);
	}

	
	@Test(expected = IllegalStateException.class)
	public void shouldThrowIllegalStateException() throws Exception {
		JwtTokenVerifier verifier = JwtTokenVerifier.create(SECRET);
		JwtTokenBuilder.from(verifier, SECRET);
	}
	
	@Test
	public void shouldIncreaseExpireTime() throws Exception {
		String token = createToken();
		JwtTokenVerifier verifier = JwtTokenVerifier.create(SECRET);
		int firstExpire = getExp(verifier, token);
		
		TimeUnit.SECONDS.sleep(2);
		
		token = JwtTokenBuilder.from(verifier, SECRET).build();
		verifier = JwtTokenVerifier.create(SECRET);
		int secondExpire = getExp(verifier, token);
		
		assertTrue(secondExpire >= firstExpire + 2);
	}

	@Test
	public void shouldRecalculateNotBeforeClaimCorrectly() {
		String token = createToken();

		JwtTokenVerifier verifier = JwtTokenVerifier.create(SECRET);
		verifier.verify(token);
		Integer nbf = (Integer) verifier.getClaims().get("nbf");
		Integer exp = getExp(verifier, token);

		assertNotNull(nbf);
		assertTrue((new Date().getTime() / 1000) > nbf);
		assertNotNull(exp);
		assertTrue((new Date().getTime() / 1000) < exp);

		JwtTokenBuilder tokenBuilder = JwtTokenBuilder.from(verifier, SECRET);
		String recreatedToken = tokenBuilder.build();

		verifier = JwtTokenVerifier.create(SECRET);
		verifier.verify(recreatedToken);
		Integer recreatedNbf = (Integer) verifier.getClaims().get("nbf");
		Integer recreatedExp = getExp(verifier, token);

		assertEquals(exp, recreatedExp);
		assertEquals((float) nbf, (float) recreatedNbf, 1);
	}

	private int getExp(JwtTokenVerifier verifier, String token) {
		verifier.verify(token);
		Map<String, Object> claims = verifier.getClaims();
		return (int) claims.get("exp");
	}

	private String createToken() {
		JwtTokenBuilder builder = JwtTokenBuilder.create(SECRET);
		return builder.userId("test").roles(Arrays.asList("role1, role2")).expirySecs(10000).notValidBeforeLeeway(5000).build();
	}
}
