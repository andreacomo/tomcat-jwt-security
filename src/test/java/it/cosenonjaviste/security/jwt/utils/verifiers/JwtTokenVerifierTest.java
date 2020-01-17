package it.cosenonjaviste.security.jwt.utils.verifiers;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import it.cosenonjaviste.security.jwt.model.JwtAdapter;
import it.cosenonjaviste.security.jwt.utils.JwtConstants;
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
		assertNotNull(verifier.verify(token));

		try {
			verifier.verify("not_a_token");
			fail("should not be here!");
		} catch (Exception e) {
			assertTrue(e instanceof JWTVerificationException);
		}
	}

	@Test
	public void testGetUserId() {
		JwtTokenVerifier verifier = JwtTokenVerifier.create(SECRET);

		JwtAdapter jwtAdapter = verifier.verify(token);
		assertNotNull(jwtAdapter);
		assertNotNull(jwtAdapter.getUserId());
		assertEquals("foo", jwtAdapter.getUserId());
	}
	
	@Test
	public void testGetRoles() {
		JwtTokenVerifier verifier = JwtTokenVerifier.create(SECRET);

		JwtAdapter jwtAdapter = verifier.verify(token);
		assertNotNull(jwtAdapter);
		assertNotNull(jwtAdapter.getRoles());
		assertEquals(2, jwtAdapter.getRoles().size());
		assertEquals(Arrays.asList("role1", "role2"), jwtAdapter.getRoles());
	}
}
