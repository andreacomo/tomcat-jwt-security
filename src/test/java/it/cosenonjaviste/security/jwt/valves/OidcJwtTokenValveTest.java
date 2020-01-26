package it.cosenonjaviste.security.jwt.valves;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import it.cosenonjaviste.security.jwt.testutils.KeyStores;
import org.apache.catalina.Container;
import org.apache.catalina.Context;
import org.apache.catalina.Realm;
import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.mockserver.junit.MockServerRule;
import org.mockserver.verify.VerificationTimes;

import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.attribute.UserPrincipal;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.TimeZone;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

public class OidcJwtTokenValveTest {

    private static final RSAKeyProvider KEY_PROVIDER = KeyStores.retrieveKey();

    private static final String OIDC_KEYS = "/protocol/openid-connect/certs";

    @Rule
    public MockitoRule mockitoRule = MockitoJUnit.rule();

    @Rule
    public MockServerRule mockServerRule = new MockServerRule(this);

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    private OidcJwtTokenValve jwtValve = new OidcJwtTokenValve();

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
    public void setUp() throws MalformedURLException {
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));

        jwtValve.setContainer(container);
        jwtValve.setNext(nextValve);
        jwtValve.setIssuerUri("http://localhost:" + mockServerRule.getPort() + OIDC_KEYS);
        jwtValve.setCustomUserIdClaim("preferred_username");
        jwtValve.setCustomRolesClaim("authorities");

        when(container.getRealm()).thenReturn(realm);
        when(request.getContext()).thenReturn(context);
    }

    @After
    public void tearDown() {
        jwtValve.defaults();
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

    @Test
    public void shouldValidateToken() throws Exception {
        mockSecurityConstraints();
        when(request.getHeader("Authorization")).thenReturn(
                "Bearer " + getTestToken());
        setupOidcServer();
        jwtValve.initInternal();

        jwtValve.invoke(request, response);

        InOrder inOrder = inOrder(request, nextValve);
        inOrder.verify(request).getHeader("Authorization");
        inOrder.verify(request).setUserPrincipal(any(UserPrincipal.class));
        inOrder.verify(request).setAuthType("TOKEN");
        inOrder.verify(nextValve).invoke(request, response);

        verifyOidcServerInvokedExactly(1);
    }

    @Test
    public void shouldValidateTokenWithAudienceConstraints() throws Exception {
        mockSecurityConstraints();
        when(request.getHeader("Authorization")).thenReturn(
                "Bearer " + getTestToken());
        setupOidcServer();
        jwtValve.setSupportedAudiences("app1, app2");
        jwtValve.initInternal();

        jwtValve.invoke(request, response);

        InOrder inOrder = inOrder(request, nextValve);
        inOrder.verify(request).getHeader("Authorization");
        inOrder.verify(request).setUserPrincipal(any(UserPrincipal.class));
        inOrder.verify(request).setAuthType("TOKEN");
        inOrder.verify(nextValve).invoke(request, response);

        verifyOidcServerInvokedExactly(1);
    }

    @Test
    public void shouldRetrieveKeysOnce() throws Exception {
        mockSecurityConstraints();
        when(request.getHeader("Authorization")).thenReturn(
                "Bearer " + getTestToken());
        setupOidcServer();
        jwtValve.initInternal();

        jwtValve.invoke(request, response);

        jwtValve.invoke(request, response);

        verifyOidcServerInvokedExactly(1);
    }

    @Test
    public void shouldFailBecauseKeyNotFound() throws Exception {
        mockSecurityConstraints();
        when(request.getHeader("Authorization")).thenReturn(
                "Bearer " + getTestToken());
        jwtValve.initInternal();

        jwtValve.invoke(request, response);

        verify(request).getHeader("Authorization");
        verify(response).sendError(401, "Failed to get key with kid jwt");
    }

    @Test
    public void shouldFailAuthBecauseOfAuthorizationHeaderNotSet() throws Exception {
        mockSecurityConstraints();

        jwtValve.invoke(request, response);

        verify(request).getHeader("Authorization");
        verify(response).sendError(401, "Authorization token not provided");
    }

    @Test
    public void shouldFailAuthBecauseOfBearerValueNotSet() throws Exception {
        mockSecurityConstraints();
        when(request.getHeader("Authorization")).thenReturn(
                "Bearer ");

        jwtValve.invoke(request, response);

        verify(request).getHeader("Authorization");
        verify(response).sendError(401, "Authorization token not provided");
    }

    @Test
    public void shouldFailAuthBecauseOfInvalidJwtToken() throws Exception {
        mockSecurityConstraints();
        when(request.getHeader("Authorization")).thenReturn(
                "Bearer invalidToken");

        jwtValve.invoke(request, response);

        verify(request).getHeader("Authorization");
        verify(response).sendError(401, "The token was expected to have 3 parts, but got 1.");
    }

    @Test
    public void shouldFailAuthBecauseOfTokenExpired() throws Exception {
        mockSecurityConstraints();
        Date expiresAt = new Date(LocalDateTime.of(2019, 1, 1, 13, 21).toInstant(ZoneOffset.UTC).toEpochMilli());
        when(request.getHeader("Authorization"))
                .thenReturn("Bearer " + getTestToken(expiresAt));
        setupOidcServer();
        jwtValve.initInternal();

        jwtValve.invoke(request, response);

        verify(request).getHeader("Authorization");
        verify(response).sendError(401, "The Token has expired on Tue Jan 01 13:21:00 UTC 2019.");

        verifyOidcServerInvokedExactly(1);
    }

    @Test
    public void shouldFailBecauseAudienceNotAllowed() throws Exception {
        mockSecurityConstraints();
        when(request.getHeader("Authorization"))
                .thenReturn("Bearer " + getTestToken());
        setupOidcServer();
        jwtValve.setSupportedAudiences("app3");
        jwtValve.initInternal();

        jwtValve.invoke(request, response);

        verify(request).getHeader("Authorization");
        verify(response).sendError(401, "Audience claim value 'app1' not supported");

        verifyOidcServerInvokedExactly(1);
    }

    private void setupOidcServer() throws IOException {
        mockServerRule.getClient()
                .when(
                        request()
                                .withPath(OIDC_KEYS)
                )
                .respond(
                        response()
                                .withBody(Files.readAllBytes(Paths.get("target/test-classes/keys.json")))
                );
    }

    private void verifyOidcServerInvokedExactly(int invocationTimes) {
        mockServerRule.getClient()
                .verify(
                        request()
                                .withPath(OIDC_KEYS),
                        VerificationTimes.exactly(invocationTimes)
                );
    }

    private void mockSecurityConstraints() {
        SecurityConstraint securityConstraint = new SecurityConstraint();
        securityConstraint.setAuthConstraint(true);
        when(realm.findSecurityConstraints(request, request.getContext()))
                .thenReturn(new SecurityConstraint[]{securityConstraint});
    }

    private String getTestToken() {
        return getTestToken(new Date(Instant.now().plusSeconds(10000).toEpochMilli()));
    }

    private String getTestToken(Date expiresAt) {
        return JWT.create()
                .withAudience("app1")
                .withClaim("preferred_username", "test")
                .withArrayClaim("authorities", new String[]{"role1", "role2"})
                .withExpiresAt(expiresAt)
                .sign(Algorithm.RSA256(KEY_PROVIDER));
    }
}