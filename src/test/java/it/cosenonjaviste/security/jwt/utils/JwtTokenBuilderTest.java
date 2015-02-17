package it.cosenonjaviste.security.jwt.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Map;

import org.junit.Test;

import com.auth0.jwt.JWTVerifier;

public class JwtTokenBuilderTest {

	private static final String SECRET = "my secret";
	
	@Test
	public void shouldContains3Claims() throws Exception {
		JwtTokenBuilder builder = JwtTokenBuilder.create(SECRET);
		String token = builder.userId("test").roles(Arrays.asList("role1, role2")).expirySecs(10000).build();
		
		assertNotNull(token);
		
		JWTVerifier verifier = new JWTVerifier(SECRET);
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
