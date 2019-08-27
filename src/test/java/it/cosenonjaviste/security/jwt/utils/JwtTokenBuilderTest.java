package it.cosenonjaviste.security.jwt.utils;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.junit.Test;

import com.auth0.jwt.JWTVerifier;

public class JwtTokenBuilderTest {

    private static final String SECRET = "my secret";

    @Test
    public void shouldContains5Claims() throws Exception {
        String token = createToken();

        assertNotNull(token);

        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SECRET)).build();
        DecodedJWT tokenObject = verifier.verify(token);

        assertNotNull(tokenObject);
        assertEquals(5, tokenObject.getClaims().size());
        assertEquals(tokenObject.getClaim(JwtConstants.USER_ID).asString(), "test");
        assertEquals(tokenObject.getClaim(JwtConstants.ROLES).asList(String.class), Arrays.asList("role1", "role2"));

        long now = System.currentTimeMillis() / 1000L;
        long timeToExpire = tokenObject.getClaim("exp").asInt() - now;
        assertTrue(timeToExpire > 0);
        assertTrue(timeToExpire <= 10000);

        int issueTime = tokenObject.getClaim("iat").asInt();
        assertTrue(issueTime <= now);
    }

    @Test(expected = IllegalStateException.class)
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
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SECRET)).build();
        DecodedJWT tokenObject = verifier.verify(token2);

        int exp = tokenObject.getClaim("exp").asInt();
        assertTrue(exp <= now + 20000);
        assertTrue(exp > now);

        int nbf = tokenObject.getClaim("nbf").asInt();
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

        assertEquals("test", verifier.getUserId());
        assertEquals(Arrays.asList("role1", "role2"), verifier.getRoles());
    }

    @Test
    public void shouldRecalculateNotBeforeClaimCorrectly() {
        String token = createToken();

        JwtTokenVerifier verifier = JwtTokenVerifier.create(SECRET);
        verifier.verify(token);
        Integer nbf = verifier.getDecodedJWT().getClaim("nbf").asInt();
        Integer exp = getExp(verifier, token);

        assertNotNull(nbf);
        long nowInSecs = new Date().getTime() / 1000;
        assertTrue(nowInSecs > nbf);
        assertNotNull(exp);
        assertTrue(nowInSecs < exp);

        JwtTokenBuilder tokenBuilder = JwtTokenBuilder.from(verifier, SECRET);
        String recreatedToken = tokenBuilder.build();

        verifier = JwtTokenVerifier.create(SECRET);
        verifier.verify(recreatedToken);
        Integer recreatedNbf = verifier.getDecodedJWT().getClaim("nbf").asInt();
        Integer recreatedExp = getExp(verifier, token);

        assertEquals(exp, recreatedExp);
        assertEquals((float) nbf, (float) recreatedNbf, 1);

        assertEquals("test", verifier.getUserId());
        assertEquals(Arrays.asList("role1", "role2"), verifier.getRoles());
    }

    @Test
    public void shouldKeepAlgorithmFromVerifier() throws Exception {
        Algorithm algorithm = Algorithm.HMAC512(SECRET);
        String token = createToken(algorithm);
        JwtTokenVerifier verifier = JwtTokenVerifier.create(algorithm);
        verifier.verify(token);

        token = JwtTokenBuilder.from(verifier, SECRET).build();

        assertEquals("HS512", JWT.decode(token).getAlgorithm());
    }

    private int getExp(JwtTokenVerifier verifier, String token) {
        verifier.verify(token);
        DecodedJWT claims = verifier.getDecodedJWT();
        return claims.getClaim("exp").asInt();
    }

    private String createToken() {
        return JwtTokenBuilder.create(SECRET)
                .userId("test")
                .roles(Arrays.asList("role1", "role2"))
                .expirySecs(10000)
                .notValidBeforeLeeway(5000)
                .build();
    }

    private String createToken(Algorithm algorithm) {
        return JwtTokenBuilder.create(algorithm)
                .userId("test")
                .roles(Arrays.asList("role1", "role2"))
                .expirySecs(10000)
                .notValidBeforeLeeway(5000)
                .build();
    }
}
