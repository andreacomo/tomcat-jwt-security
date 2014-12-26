package it.cosenonjaviste.security.jwt.utils;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

import org.junit.Test;

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.internal.org.apache.commons.codec.binary.Base64;

public class JwtTokenBuilderTest {

	private static final String SECRET = "my secret";
	
	private static final String SECRET_BASE64 = Base64.encodeBase64String(SECRET.getBytes(StandardCharsets.UTF_8));

	@Test
	public void shouldContains3Claims() throws Exception {
		JwtTokenBuilder builder = JwtTokenBuilder.create(SECRET);
		String token = builder.userId("test").roles(Arrays.asList("role1, role2")).expirySecs(10000).build();
		
		assertNotNull(token);
		
		JWTVerifier verifier = new JWTVerifier(SECRET_BASE64);
		Map<String, Object> tokenObject = verifier.verify(token);
		
		assertNotNull(tokenObject);
		assertEquals(3, tokenObject.size());
		assertEquals(tokenObject.get(JwtConstants.USER_ID), "test");
		assertEquals(tokenObject.get(JwtConstants.ROLES), Arrays.asList("role1, role2"));
		
		long timeToExpire = ((int)tokenObject.get("exp")) - (System.currentTimeMillis() /1000L);
		assertTrue(timeToExpire > 0);
		assertTrue(timeToExpire <= 10000);
	}

	@Test(expected=IllegalStateException.class)
	public void shouldBeEmptyAndInvalid() throws Exception {
		JwtTokenBuilder.create(SECRET).build();
	}
}
