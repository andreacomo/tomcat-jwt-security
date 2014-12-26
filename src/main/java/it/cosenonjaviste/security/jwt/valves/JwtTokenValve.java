package it.cosenonjaviste.security.jwt.valves;

import it.cosenonjaviste.security.jwt.utils.JwtConstants;
import it.cosenonjaviste.security.jwt.utils.JwtTokenVerifier;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.Container;
import org.apache.catalina.Context;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.SecurityConstraint;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.valves.ValveBase;

public class JwtTokenValve extends ValveBase {

	private Context context;

	private String secret;

	@Override
	public void invoke(Request request, Response response) throws IOException,
			ServletException {

		SecurityConstraint[] constraints = this.container.getRealm()
				.findSecurityConstraints(request, this.context);

		if ((constraints == null && !context.getPreemptiveAuthentication())
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
			JwtTokenVerifier tokenVerifier = JwtTokenVerifier.create(secret, false);
			if (tokenVerifier.verify(token)) {
				request.setUserPrincipal(createPrincipalFromToken(tokenVerifier));
				request.setAuthType("TOKEN");
				this.getNext().invoke(request, response);
			} else {
				response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
						"Token not valid. Please login first");
			}
		} else {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
					"Please login first");
		}
	}

	private GenericPrincipal createPrincipalFromToken(JwtTokenVerifier tokenVerifier) {
		return new GenericPrincipal(tokenVerifier.getUserId(), null, tokenVerifier.getRoles());
	}

	/**
	 * Set the Container to which this Valve is attached.
	 *
	 * @param container
	 *            The container to which we are attached
	 */
	@Override
	public void setContainer(Container container) {

		if (container != null && !(container instanceof Context))
			throw new IllegalArgumentException(
					sm.getString("authenticator.notContext"));

		super.setContainer(container);
		this.context = (Context) container;

	}

	public void setSecret(String secret) {
		this.secret = secret;
	}

	public void setContext(Context context) {
		this.context = context;
	}

}
