package it.cosenonjaviste.security.jwt.utils.verifiers;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import it.cosenonjaviste.security.jwt.model.JwtAdapter;
import it.cosenonjaviste.security.jwt.testutils.KeyStores;
import it.cosenonjaviste.security.jwt.utils.JwtConstants;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.*;

public class JwtTokenVerifierTest {

	private static final String SECRET = "a secret";
	private static final RSAKeyProvider KEY_PROVIDER = KeyStores.retrieveKey();
	private static String hmacToken;
	private static String rsaToken;
	
	@BeforeClass
	public static void before() {
		hmacToken = JWT.create()
				.withClaim(JwtConstants.USER_ID, "foo")
				.withArrayClaim(JwtConstants.ROLES, new String[] {"role1", "role2"})
				.sign(Algorithm.HMAC256(SECRET));

		rsaToken = JWT.create()
				.withClaim(JwtConstants.USER_ID, "foo")
				.withArrayClaim(JwtConstants.ROLES, new String[] {"role1", "role2"})
				.sign(Algorithm.RSA256(KEY_PROVIDER));
	}
	
	@Test
	public void testVerifyWithSecret() {
		JwtTokenVerifier verifier = JwtTokenVerifier.create(SECRET);
		assertNotNull(verifier.verify(hmacToken));

		try {
			verifier.verify("not_a_token");
			fail("should not be here!");
		} catch (Exception e) {
			assertTrue(e instanceof JWTVerificationException);
		}
	}

	@Test
	public void testVerifyWithKey() {
		JwtTokenVerifier verifier = JwtTokenVerifier.create(KEY_PROVIDER);
		assertNotNull(verifier.verify(rsaToken));

		try {
			verifier.verify("not_a_token");
			fail("should not be here!");
		} catch (Exception e) {
			assertTrue(e instanceof JWTVerificationException);
		}
	}

	@Test
	public void testGetUserIdWithSecret() {
		JwtTokenVerifier verifier = JwtTokenVerifier.create(SECRET);

		JwtAdapter jwtAdapter = verifier.verify(hmacToken);
		assertNotNull(jwtAdapter);
		assertNotNull(jwtAdapter.getUserId());
		assertEquals("foo", jwtAdapter.getUserId());
	}

	@Test
	public void testGetUserIdWithKey() {
		JwtTokenVerifier verifier = JwtTokenVerifier.create(KEY_PROVIDER);

		JwtAdapter jwtAdapter = verifier.verify(rsaToken);
		assertNotNull(jwtAdapter);
		assertNotNull(jwtAdapter.getUserId());
		assertEquals("foo", jwtAdapter.getUserId());
	}

	@Test
	public void testGetRolesWithSecret() {
		JwtTokenVerifier verifier = JwtTokenVerifier.create(SECRET);

		JwtAdapter jwtAdapter = verifier.verify(hmacToken);
		assertNotNull(jwtAdapter);
		assertNotNull(jwtAdapter.getRoles());
		assertEquals(2, jwtAdapter.getRoles().size());
		assertEquals(Arrays.asList("role1", "role2"), jwtAdapter.getRoles());
	}

	@Test
	public void testGetRolesWithKey() {
		JwtTokenVerifier verifier = JwtTokenVerifier.create(KEY_PROVIDER);

		JwtAdapter jwtAdapter = verifier.verify(rsaToken);
		assertNotNull(jwtAdapter);
		assertNotNull(jwtAdapter.getRoles());
		assertEquals(2, jwtAdapter.getRoles().size());
		assertEquals(Arrays.asList("role1", "role2"), jwtAdapter.getRoles());
	}
}
