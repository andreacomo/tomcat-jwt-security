package it.cosenonjaviste.security.jwt.valves;

import it.cosenonjaviste.security.jwt.catalinawriters.ResponseWriter;
import it.cosenonjaviste.security.jwt.model.AuthErrorResponse;
import it.cosenonjaviste.security.jwt.utils.JwtConstants;
import it.cosenonjaviste.security.jwt.utils.JwtTokenVerifier;

import java.io.IOException;
import java.nio.file.attribute.UserPrincipal;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.SecurityConstraint;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.valves.ValveBase;

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
	
	private boolean isBase64 = false;

	@Override
	public void invoke(Request request, Response response) throws IOException,
			ServletException {

		SecurityConstraint[] constraints = this.container.getRealm()
				.findSecurityConstraints(request, request.getContext());

		if ((constraints == null && !request.getContext().getPreemptiveAuthentication())
				|| !hasAuthContraint(constraints)) {
			this.getNext().invoke(request, response); 
		} else {
			handleAuthentication(request, response);
		}

	}

	private boolean hasAuthContraint(SecurityConstraint[] constraints) {
		boolean authConstraint = true;
		for (SecurityConstraint securityConstraint : constraints) {
			authConstraint &= securityConstraint.getAuthConstraint();
		}
		return authConstraint;
	}

	private void handleAuthentication(Request request, Response response)
			throws IOException, ServletException {

		String token = request.getHeader(JwtConstants.AUTH_HEADER);
		if (token != null) {
			JwtTokenVerifier tokenVerifier = JwtTokenVerifier.create(secret, isBase64);
			if (tokenVerifier.verify(token)) {
				request.setUserPrincipal(createPrincipalFromToken(tokenVerifier));
				request.setAuthType("TOKEN");
				this.getNext().invoke(request, response);
			} else {
				sendUnauthorizedError(request, response, "Token not valid. Please login first");
			}
		} else {
			sendUnauthorizedError(request, response, "Please login first");
		}
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

	public void setBase64(boolean isBase64) {
		this.isBase64 = isBase64;
	}
}
