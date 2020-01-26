package it.cosenonjaviste.security.jwt.utils.verifiers;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import it.cosenonjaviste.security.jwt.utils.JwtConstants;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.time.Instant;
import java.util.Date;

import static org.junit.Assert.assertEquals;

public class HmacSignedVerifierStrategyTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    private static final String SECRET = "a secret";

    @Test
    public void shouldVerifyHS256() {
        verifyByAlgorithm(Algorithm.HMAC256(SECRET));
    }

    @Test
    public void shouldVerifyHS384() {
        verifyByAlgorithm(Algorithm.HMAC384(SECRET));
    }

    @Test
    public void shouldVerifyHS512() {
        verifyByAlgorithm(Algorithm.HMAC512(SECRET));
    }

    @Test
    public void shouldNotVerifyDueToAlgorithmNotSupported() {
        expectedException.expect(JWTVerificationException.class);
        expectedException.expectMessage("With secret text, only HMAC algorithms are supported");

        verifyByAlgorithm(Algorithm.none());
    }

    @Test
    public void shouldNotVerifyDueToTokenExpired() {
        expectedException.expect(TokenExpiredException.class);
        expectedException.expectMessage("The Token has expired on");

        String token = JWT.create()
                .withExpiresAt(new Date(Instant.now().minusSeconds(10000).toEpochMilli()))
                .sign(Algorithm.HMAC384(SECRET));

        HmacSignedVerifierStrategy verifierStrategy = new HmacSignedVerifierStrategy(SECRET);
        verifierStrategy.verify(JWT.decode(token));
    }

    private void verifyByAlgorithm(Algorithm algorithm) {
        String jwt = createJwt(algorithm);

        HmacSignedVerifierStrategy verifierStrategy = new HmacSignedVerifierStrategy(SECRET);
        Algorithm extractedAlgorithm = verifierStrategy.verify(JWT.decode(jwt));

        assertEquals(algorithm.getName(), extractedAlgorithm.getName());
    }

    private String createJwt(Algorithm algorithm) {
        return JWT.create()
                .withClaim(JwtConstants.USER_ID, "foo")
                .withArrayClaim(JwtConstants.ROLES, new String[]{"role1", "role2"})
                .sign(algorithm);
    }
}