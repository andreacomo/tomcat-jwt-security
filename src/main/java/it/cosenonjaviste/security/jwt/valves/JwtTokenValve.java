package it.cosenonjaviste.security.jwt.valves;

import com.auth0.jwt.exceptions.JWTVerificationException;
import it.cosenonjaviste.security.jwt.catalinawriters.ResponseWriter;
import it.cosenonjaviste.security.jwt.model.AuthErrorResponse;
import it.cosenonjaviste.security.jwt.model.JwtAdapter;
import it.cosenonjaviste.security.jwt.utils.JwtConstants;
import it.cosenonjaviste.security.jwt.utils.verifiers.JwtTokenVerifier;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.valves.ValveBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.file.attribute.UserPrincipal;
import java.util.stream.Stream;

/**
 * Perform a JWT authentication on requester resource.
 * 
 * Expected a JWT token containing two additional claims over standard ones:
 * <ul>
 * 	<li><em>userId</em>: username authenticated by realm system</li>
 * 	<li><em>roles</em>: realm roles associated to username</li>
 * </ul>
 * 
 * A new {@link UserPrincipal} will be created upon <tt>userId</tt> and <tt>roles</tt> values: no need to authenticate each request, user status is provided by JWT token!
 * <br>
 * Expected header for JWT token is <strong><tt>X-Auth</tt></strong>
 * 
 * @author acomo
 *
 */
public abstract class JwtTokenValve extends ValveBase {

	private static final Log LOG = LogFactory.getLog(JwtTokenValve.class);

	private JwtTokenVerifier tokenVerifier;

	private String cookieName;

	private String customUserIdClaim;

	private String customRolesClaim;

	@Override
	protected void initInternal() throws LifecycleException {
		super.initInternal();
		this.tokenVerifier = createTokenVerifier(customUserIdClaim, customRolesClaim);
	}

	/**
	 * Creates a {@link JwtTokenVerifier} instance from keystore
	 *
	 * @param customUserIdClaim claim to use for identifying user id
	 * @param customRolesClaim claim to use fot identifies user roles
	 *
	 * @return {@link JwtTokenVerifier} instance
	 */
	protected abstract JwtTokenVerifier createTokenVerifier(String customUserIdClaim, String customRolesClaim);

	@Override
	public void invoke(Request request, Response response) throws IOException,
			ServletException {

		SecurityConstraint[] constraints = this.container.getRealm()
				.findSecurityConstraints(request, request.getContext());

		if ((constraints == null && !request.getContext().getPreemptiveAuthentication())
				|| !hasAuthConstraint(constraints)) {
			this.getNext().invoke(request, response); 
		} else {
			handleAuthentication(request, response);
		}

	}

	private boolean hasAuthConstraint(SecurityConstraint[] constraints) {
		if (constraints != null) {
			boolean authConstraint = true;
			for (SecurityConstraint securityConstraint : constraints) {
				authConstraint &= securityConstraint.getAuthConstraint();
			}
			return authConstraint;
		} else {
			return false;
		}

	}

	private void handleAuthentication(Request request, Response response)
			throws IOException, ServletException {

		String token = getToken(request);
		if (token != null) {
			try {
				JwtAdapter jwt = tokenVerifier.verify(token);
				request.setUserPrincipal(createPrincipalFromToken(jwt));
				request.setAuthType("TOKEN");
				beforeNext(response, jwt);
				this.getNext().invoke(request, response);
			} catch (JWTVerificationException e) {
				LOG.error(e.getMessage());
				sendUnauthorizedError(request, response, "Token not valid. Cause: " + e.getMessage());
			}
		} else {
			sendUnauthorizedError(request, response, "Please login first");
		}
	}

	protected void beforeNext(Response response, JwtAdapter jwt) {
	}

	private String getCookieValueByName(Request request, String name){
		if (name == null) {
			return null;
		}

		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			return Stream.of(cookies)
					.filter(cookie -> cookie.getName().equalsIgnoreCase(name))
					.findFirst()
					.map(Cookie::getValue)
					.orElse(null);
		}
	    return null;
	}

	/**
	 * Look for authentication token with following priorities
	 * <ul>
	 *     <li>in request header <em>X-Auth</em></li>
	 *     <li>in request header <em>Authorization</em> (value preceded by <em>Bearer</em>)</li>
	 *     <li>in request query parameter <em>access_token</em></li>
	 *     <li>in a cookie configured by property <em>cookieName</em></li>
	 * </ul>
	 *
	 * @param request
	 * @return token or null
	 */
	private String getToken(Request request) {
		String xAuthToken = request.getHeader(JwtConstants.AUTH_HEADER);
		if (xAuthToken == null) {
			String bearerToken = request.getHeader("Authorization");
			if (bearerToken != null && bearerToken.toLowerCase().startsWith("bearer ")) {
				return bearerToken.replaceAll("(?i)Bearer (.*)", "$1");
			} else if (request.getParameter(JwtConstants.AUTH_PARAM) != null) {
				return request.getParameter(JwtConstants.AUTH_PARAM);
			} else {
				return getCookieValueByName(request, cookieName);
			}
		} else {
			return xAuthToken;
		}
	}

	private GenericPrincipal createPrincipalFromToken(JwtAdapter jwt) {
		return new GenericPrincipal(jwt.getUserId(), null, jwt.getRoles());
	}

	protected void sendUnauthorizedError(Request request, Response response, String message) throws IOException {
		ResponseWriter.get(request.getHeader("accept")).write(response, HttpServletResponse.SC_UNAUTHORIZED, new AuthErrorResponse(message));
	}

	public void setCookieName(String cookieName) {
		this.cookieName = cookieName;
	}

	public void setCustomUserIdClaim(String customUserIdClaim) {
		this.customUserIdClaim = customUserIdClaim;
	}

	public void setCustomRolesClaim(String customRolesClaim) {
		this.customRolesClaim = customRolesClaim;
	}
}
