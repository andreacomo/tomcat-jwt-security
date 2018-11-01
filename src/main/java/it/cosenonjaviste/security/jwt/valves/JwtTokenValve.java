package it.cosenonjaviste.security.jwt.valves;

import it.cosenonjaviste.security.jwt.catalinawriters.ResponseWriter;
import it.cosenonjaviste.security.jwt.model.AuthErrorResponse;
import it.cosenonjaviste.security.jwt.utils.JwtConstants;
import it.cosenonjaviste.security.jwt.utils.JwtTokenBuilder;
import it.cosenonjaviste.security.jwt.utils.JwtTokenVerifier;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.valves.ValveBase;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.file.attribute.UserPrincipal;

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
public class JwtTokenValve extends ValveBase {

	private String secret;
	
	private boolean updateExpire;
	
	private String cookieName;

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
			JwtTokenVerifier tokenVerifier = JwtTokenVerifier.create(secret);
			if (tokenVerifier.verify(token)) {
				request.setUserPrincipal(createPrincipalFromToken(tokenVerifier));
				request.setAuthType("TOKEN");
				if (this.updateExpire) {
					updateToken(tokenVerifier, response);
				}
				this.getNext().invoke(request, response);
			} else {
				sendUnauthorizedError(request, response, "Token not valid. Please login first");
			}
		} else {
			sendUnauthorizedError(request, response, "Please login first");
		}
	}
	
	private String getCookieValueByName(Request request, String name){
		if (name == null) {
			return null;
		}

		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().equalsIgnoreCase(name)) {
					return cookie.getValue();
				}
			}
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

	private void updateToken(JwtTokenVerifier tokenVerifier, Response response) {
		String newToken = JwtTokenBuilder.from(tokenVerifier, secret).build();
		response.setHeader(JwtConstants.AUTH_HEADER, newToken);
	}

	private GenericPrincipal createPrincipalFromToken(JwtTokenVerifier tokenVerifier) {
		return new GenericPrincipal(tokenVerifier.getUserId(), null, tokenVerifier.getRoles());
	}

	protected void sendUnauthorizedError(Request request, Response response, String message) throws IOException {
		ResponseWriter.get(request.getHeader("accept")).write(response, HttpServletResponse.SC_UNAUTHORIZED, new AuthErrorResponse(message));
	}

	public void setSecret(String secret) {
		this.secret = secret;
	}
	
	/**
	 * Updates expire time on each request
	 * 
	 * @param updateExpire
	 */
	public void setUpdateExpire(boolean updateExpire) {
		this.updateExpire = updateExpire;
	}

	public void setCookieName(String cookieName) {
		this.cookieName = cookieName;
	}
}
