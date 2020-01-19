package it.cosenonjaviste.security.jwt.valves;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import it.cosenonjaviste.security.jwt.exceptions.ValveInitializationException;
import it.cosenonjaviste.security.jwt.testutils.KeyStores;
import it.cosenonjaviste.security.jwt.utils.JwtConstants;
import org.apache.catalina.*;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import javax.servlet.http.Cookie;
import java.nio.file.attribute.UserPrincipal;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class RsaJwtTokenValveTest {

    private static final RSAKeyProvider KEY_PROVIDER = KeyStores.retrieveKey();

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    private RsaJwtTokenValve jwtValve = new RsaJwtTokenValve();

    // Catalina mocks
    @Mock
    private Container container;

    @Mock
    private Realm realm;

    @Mock
    private Context context;

    @Mock
    private Request request;

    @Mock
    private Response response;

    @Mock
    private Valve nextValve;

    @Before
    public void setUp() throws LifecycleException {
        jwtValve.setContainer(container);
        jwtValve.setNext(nextValve);
        jwtValve.setKeystorePath("target/test-classes/" + KeyStores.KEYSTORE);
        jwtValve.setKeystorePassword(KeyStores.KEYSTORE_PASSWORD);

        when(container.getRealm()).thenReturn(realm);
        when(request.getContext()).thenReturn(context);

        jwtValve.initInternal();
    }

    /**
     * @throws Exception
     */
    @Test
    public void shouldInvokeNextValveWithoutAuth() throws Exception {
        when(realm.findSecurityConstraints(request, request.getContext()))
                .thenReturn(null);

        jwtValve.invoke(request, response);

        verify(nextValve).invoke(request, response);
    }

    /**
     * @throws Exception
     */
    @Test
    public void shouldPassAuthInHeader() throws Exception {
        SecurityConstraint securityConstraint = new SecurityConstraint();
        securityConstraint.setAuthConstraint(true);
        when(realm.findSecurityConstraints(request, request.getContext()))
                .thenReturn(new SecurityConstraint[] { securityConstraint });
        when(request.getHeader(JwtConstants.AUTH_HEADER)).thenReturn(
                getTestToken());

        jwtValve.invoke(request, response);

        InOrder inOrder = inOrder(request, nextValve);
        inOrder.verify(request).getHeader(JwtConstants.AUTH_HEADER);
        inOrder.verify(request).setUserPrincipal(any(UserPrincipal.class));
        inOrder.verify(request).setAuthType("TOKEN");
        inOrder.verify(nextValve).invoke(request, response);
    }

    /**
     * @throws Exception
     */
    @Test
    public void shouldPassAuthInStandardHeader() throws Exception {
        SecurityConstraint securityConstraint = new SecurityConstraint();
        securityConstraint.setAuthConstraint(true);
        when(realm.findSecurityConstraints(request, request.getContext()))
                .thenReturn(new SecurityConstraint[] { securityConstraint });
        when(request.getHeader("Authorization")).thenReturn(
                "Bearer " + getTestToken());

        jwtValve.invoke(request, response);

        InOrder inOrder = inOrder(request, nextValve);
        inOrder.verify(request).getHeader("Authorization");
        inOrder.verify(request).setUserPrincipal(any(UserPrincipal.class));
        inOrder.verify(request).setAuthType("TOKEN");
        inOrder.verify(nextValve).invoke(request, response);
    }

    /**
     * @throws Exception
     */
    @Test
    public void shouldPassLowercaseBearerAuthInStandardHeader() throws Exception {
        SecurityConstraint securityConstraint = new SecurityConstraint();
        securityConstraint.setAuthConstraint(true);
        when(realm.findSecurityConstraints(request, request.getContext()))
                .thenReturn(new SecurityConstraint[] { securityConstraint });
        when(request.getHeader("Authorization")).thenReturn(
                "bearer " + getTestToken());

        jwtValve.invoke(request, response);

        InOrder inOrder = inOrder(request, nextValve);
        inOrder.verify(request).getHeader("Authorization");
        inOrder.verify(request).setUserPrincipal(any(UserPrincipal.class));
        inOrder.verify(request).setAuthType("TOKEN");
        inOrder.verify(nextValve).invoke(request, response);
    }

    /**
     * @throws Exception
     */
    @Test
    public void shouldPassAuthInRequestParam() throws Exception {
        SecurityConstraint securityConstraint = new SecurityConstraint();
        securityConstraint.setAuthConstraint(true);
        when(realm.findSecurityConstraints(request, request.getContext()))
                .thenReturn(new SecurityConstraint[] { securityConstraint });
        when(request.getParameter(JwtConstants.AUTH_PARAM)).thenReturn(
                getTestToken());

        jwtValve.invoke(request, response);

        InOrder inOrder = inOrder(request, nextValve);
        inOrder.verify(request, times(2)).getParameter(JwtConstants.AUTH_PARAM);
        inOrder.verify(request).setUserPrincipal(any(UserPrincipal.class));
        inOrder.verify(request).setAuthType("TOKEN");
        inOrder.verify(nextValve).invoke(request, response);
    }

    /**
     * @throws Exception
     */
    @Test
    public void shouldPassAuthInCookie() throws Exception {
        try {
            String cookieName = "auth_token";
            jwtValve.setCookieName(cookieName);
            SecurityConstraint securityConstraint = new SecurityConstraint();
            securityConstraint.setAuthConstraint(true);
            when(realm.findSecurityConstraints(request, request.getContext()))
                    .thenReturn(new SecurityConstraint[]{securityConstraint});
            when(request.getCookies()).thenReturn(newCookies(cookieName));

            jwtValve.invoke(request, response);

            InOrder inOrder = inOrder(request, nextValve);
            inOrder.verify(request).getParameter(JwtConstants.AUTH_PARAM);
            inOrder.verify(request).setUserPrincipal(any(UserPrincipal.class));
            inOrder.verify(request).setAuthType("TOKEN");
            inOrder.verify(nextValve).invoke(request, response);
        } finally {
            jwtValve.setCookieName(null);
        }
    }

    /**
     * @throws Exception
     */
    @Test
    public void shouldFailAuthBecauseOfTokenNotSet() throws Exception {
        SecurityConstraint securityConstraint = new SecurityConstraint();
        securityConstraint.setAuthConstraint(true);
        when(realm.findSecurityConstraints(request, request.getContext()))
                .thenReturn(new SecurityConstraint[] { securityConstraint });

        jwtValve.invoke(request, response);

        verify(request).getHeader(JwtConstants.AUTH_HEADER);
        verify(request).getParameter(JwtConstants.AUTH_PARAM);
        verify(response).sendError(401, "Please login first");
    }

    /**
     * @throws Exception
     */
    @Test
    public void shouldFailAuthBecauseOfTokenExpired() throws Exception {
        SecurityConstraint securityConstraint = new SecurityConstraint();
        securityConstraint.setAuthConstraint(true);
        when(realm.findSecurityConstraints(request, request.getContext()))
                .thenReturn(new SecurityConstraint[] { securityConstraint });
        Date expiresAt = new Date(LocalDateTime.of(2019, 1, 1, 13, 21).toInstant(ZoneOffset.UTC).toEpochMilli());
        when(request.getHeader(JwtConstants.AUTH_HEADER)).thenReturn(getTestToken(expiresAt));

        jwtValve.invoke(request, response);

        verify(request).getHeader(JwtConstants.AUTH_HEADER);
        verify(response).sendError(401, "Token not valid. Cause: The Token has expired on Tue Jan 01 14:21:00 CET 2019.");
    }

    /**
     * @throws Exception
     */
    @Test
    public void shouldFailAuthBecauseOfKeyAliasNotFound() throws Exception {
        expectedException.expect(ValveInitializationException.class);
        expectedException.expectMessage("Alias 'not_an_alias' not found in keystore");

        RsaJwtTokenValve valve = new RsaJwtTokenValve();
        valve.setContainer(container);
        valve.setNext(nextValve);
        valve.setKeystorePath("target/test-classes/" + KeyStores.KEYSTORE);
        valve.setKeystorePassword(KeyStores.KEYSTORE_PASSWORD);
        valve.setKeyPairsAlias("not_an_alias");
        valve.initInternal();
    }

    /**
     * @throws Exception
     */
    @Test
    public void shouldFailAuthBecauseOfKeyStoreNotFound() throws Exception {
        expectedException.expect(ValveInitializationException.class);
        expectedException.expectMessage("path/not/found (No such file or directory)");

        RsaJwtTokenValve valve = new RsaJwtTokenValve();
        valve.setContainer(container);
        valve.setNext(nextValve);
        valve.setKeystorePath("path/not/found");
        valve.setKeystorePassword(KeyStores.KEYSTORE_PASSWORD);
        valve.initInternal();
    }

    /**
     * @throws Exception
     */
    @Test
    public void shouldFailAuthBecauseOfKeyStorePasswordInvalid() throws Exception {
        expectedException.expect(ValveInitializationException.class);
        expectedException.expectMessage("Keystore was tampered with, or password was incorrect");

        RsaJwtTokenValve valve = new RsaJwtTokenValve();
        valve.setContainer(container);
        valve.setNext(nextValve);
        valve.setKeystorePath("target/test-classes/" + KeyStores.KEYSTORE);
        valve.setKeystorePassword("invalid_password");
        valve.initInternal();
    }

    private String getTestToken() {
        return getTestToken(new Date(Instant.now().plusSeconds(10000).toEpochMilli()));
    }

    private String getTestToken(Date expiresAt) {
        return JWT.create()
                .withSubject("test")
                .withArrayClaim("authorities", new String[] {"role1", "role2"})
                .withExpiresAt(expiresAt)
                .sign(Algorithm.RSA256(KEY_PROVIDER));
    }

    private Cookie[] newCookies(String cookieName) {
        return new Cookie[] {new Cookie(cookieName, getTestToken())};
    }

}