package it.cosenonjaviste.security.jwt.utils.verifiers;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import it.cosenonjaviste.security.jwt.utils.JwtConstants;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;

import static it.cosenonjaviste.security.jwt.testutils.KeyStores.retrieveKey;
import static org.junit.Assert.assertEquals;

public class RsaSignedVerifierStrategyTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void shouldVerifyRS256() {
        RSAKeyProvider keyProvider = retrieveKey();
        verifyByAlgorithm(Algorithm.RSA256(keyProvider), keyProvider);
    }

    @Test
    public void shouldVerifyRS3384() {
        RSAKeyProvider keyProvider = retrieveKey();
        verifyByAlgorithm(Algorithm.RSA384(keyProvider), keyProvider);
    }

    @Test
    public void shouldVerifyRS512() {
        RSAKeyProvider keyProvider = retrieveKey();
        verifyByAlgorithm(Algorithm.RSA512(keyProvider), keyProvider);
    }

    @Test
    public void shouldNotVerifyDueToAlgorithmNotSupported() {
        expectedException.expect(JWTVerificationException.class);
        expectedException.expectMessage("With a keystore, only RSA algorithms are supported");

        verifyByAlgorithm(Algorithm.none(), retrieveKey());
    }

    @Test
    public void shouldNotVerifyDueToTokenExpired() {
        expectedException.expect(TokenExpiredException.class);
        expectedException.expectMessage("The Token has expired on");

        RSAKeyProvider keyProvider = retrieveKey();
        String token = JWT.create()
                .withExpiresAt(new Date(Instant.now().minusSeconds(10000).toEpochMilli()))
                .sign(Algorithm.RSA512(keyProvider));

        RsaSignedVerifierStrategy verifierStrategy = new RsaSignedVerifierStrategy(keyProvider);
        verifierStrategy.verify(JWT.decode(token));
    }

    private void verifyByAlgorithm(Algorithm algorithm, RSAKeyProvider keyProvider) {
        String jwt = createJwt(algorithm);

        RsaSignedVerifierStrategy verifierStrategy = new RsaSignedVerifierStrategy(keyProvider);
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