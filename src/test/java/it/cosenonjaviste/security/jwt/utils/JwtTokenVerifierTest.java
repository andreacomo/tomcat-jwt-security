package it.cosenonjaviste.security.jwt.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.*;

public class JwtTokenVerifierTest {

	private static final String SECRET = "a secret";
	private static String token;
	
	@BeforeClass
	public static void before() {
		token = JWT.create()
				.withClaim(JwtConstants.USER_ID, "foo")
				.withArrayClaim(JwtConstants.ROLES, new String[] {"role1", "role2"})
				.sign(Algorithm.HMAC256(SECRET));
	}
	
	@Test
	public void testVerify() {
		JwtTokenVerifier verifier = JwtTokenVerifier.create(SECRET);
		assertTrue(verifier.verify(token));

		assertFalse(verifier.verify("not_a_token"));
	}

	@Test
	public void testVerifyCreatingWithCustomAlgorithm() {
		Algorithm algorithm = Algorithm.HMAC512(SECRET);
		JwtTokenVerifier verifier = JwtTokenVerifier.create(algorithm);
		assertFalse(verifier.verify(token));

		String newToken = JWT.create()
				.withClaim(JwtConstants.USER_ID, "foo")
				.withArrayClaim(JwtConstants.ROLES, new String[]{"role1", "role2"})
				.sign(algorithm);
		assertTrue(verifier.verify(newToken));
	}

	@Test
	public void testVerifyOrThrow() {
		JwtTokenVerifier verifier = JwtTokenVerifier.create(SECRET);
		verifier.verifyOrThrow(token);

		try {
			verifier.verifyOrThrow("not_a_token");
			fail("should not be here!");
		} catch (Exception e) {
			assertTrue(e instanceof JWTVerificationException);
		}
	}

	@Test
	public void testGetUserId() {
		JwtTokenVerifier verifier = JwtTokenVerifier.create(SECRET);
		
		assertTrue(verifier.verify(token));
		assertNotNull(verifier.getUserId());
		assertEquals("foo", verifier.getUserId());
	}
	
	@Test
	public void testGetRoles() {
		JwtTokenVerifier verifier = JwtTokenVerifier.create(SECRET);
		
		assertTrue(verifier.verify(token));
		assertNotNull(verifier.getRoles());
		assertEquals(2, verifier.getRoles().size());
		assertEquals(Arrays.asList("role1", "role2"), verifier.getRoles());
	}
	
	@Test(expected = IllegalStateException.class)
	public void shouldThrowIllegalStateExceptionWhenGetUserId() {
		JwtTokenVerifier verifier = JwtTokenVerifier.create(SECRET);
		
		assertNotNull(verifier.getUserId());
	}

	@Test(expected = IllegalStateException.class)
	public void shouldThrowIllegalStateExceptionWhenGetRoles() {
		JwtTokenVerifier verifier = JwtTokenVerifier.create(SECRET);

		assertNotNull(verifier.getRoles());
	}

}
