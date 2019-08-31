package it.cosenonjaviste.security.jwt.valves;

import it.cosenonjaviste.security.jwt.utils.JwtConstants;
import it.cosenonjaviste.security.jwt.utils.JwtTokenBuilder;
import org.apache.catalina.Container;
import org.apache.catalina.Context;
import org.apache.catalina.Realm;
import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import javax.servlet.http.Cookie;
import java.nio.file.attribute.UserPrincipal;
import java.util.Arrays;

import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class JwtTokenValveTest {

	private static final String SECRET = "my secret";

	private JwtTokenValve jwtValve = new JwtTokenValve();

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
	public void setUp() {
		jwtValve.setContainer(container);
		jwtValve.setNext(nextValve);
		jwtValve.setSecret(SECRET);

		when(container.getRealm()).thenReturn(realm);
		when(request.getContext()).thenReturn(context);
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
	public void shouldFailAuthBecauseOfTokenInvalid() throws Exception {
		SecurityConstraint securityConstraint = new SecurityConstraint();
		securityConstraint.setAuthConstraint(true);
		when(realm.findSecurityConstraints(request, request.getContext()))
				.thenReturn(new SecurityConstraint[] { securityConstraint });
		when(request.getHeader(JwtConstants.AUTH_HEADER)).thenReturn("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE0NDE1OTI3ODEsInVzZXJJZCI6InRlc3QiLCJyb2xlcyI6WyJyb2xlMSwgcm9sZTIiXX0.ObRZMakmlfdw75VCA8FuyFBpNOSu-x3wea9-_NpYJ9");

		jwtValve.invoke(request, response);

		verify(request).getHeader(JwtConstants.AUTH_HEADER);
		verify(response).sendError(401, "Token not valid. Please login first");
	}

	/**
	 * @throws Exception
	 */
	@Test
	public void shouldRenewToken() throws Exception {
		SecurityConstraint securityConstraint = new SecurityConstraint();
		securityConstraint.setAuthConstraint(true);
		when(realm.findSecurityConstraints(request, request.getContext()))
				.thenReturn(new SecurityConstraint[] { securityConstraint });
		when(request.getHeader(JwtConstants.AUTH_HEADER)).thenReturn(
				getTestToken());

		jwtValve.setUpdateExpire(true);
		jwtValve.invoke(request, response);

		verify(response).setHeader(eq(JwtConstants.AUTH_HEADER), anyString());
	}

	private String getTestToken() {
		return JwtTokenBuilder.create(SECRET).userId("test")
				.roles(Arrays.asList("role1", "role2")).expirySecs(10000).build();
	}

	private Cookie[] newCookies(String cookieName) {
		return new Cookie[] {new Cookie(cookieName, getTestToken())};
	}
}
