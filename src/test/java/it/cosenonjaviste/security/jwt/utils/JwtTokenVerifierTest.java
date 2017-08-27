package it.cosenonjaviste.security.jwt.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.junit.BeforeClass;
import org.junit.Test;

import com.auth0.jwt.JWTSigner;

public class JwtTokenVerifierTest {

	private static final String SECRET = "a secret";
	private static String token;
	
	@BeforeClass
	public static void before() {
		Map<String, Object> claims = new HashMap<String, Object>();
		claims.put(JwtConstants.USER_ID, "foo");
		claims.put(JwtConstants.ROLES, Arrays.asList("role1", "role2"));
		
		JWTSigner signer = new JWTSigner(SECRET);
		token = signer.sign(claims);
	}
	
	@Test
	public void testVerify() {
		JwtTokenVerifier verifier = JwtTokenVerifier.create(SECRET);
		assertTrue(verifier.verify(token));
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
	public void shouldThrowIllegalStateException() throws Exception {
		JwtTokenVerifier verifier = JwtTokenVerifier.create(SECRET);
		
		assertNotNull(verifier.getUserId());
	}

}
