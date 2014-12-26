package it.cosenonjaviste.security.jwt.valves;

import it.cosenonjaviste.security.jwt.utils.JwtConstants;
import it.cosenonjaviste.security.jwt.utils.JwtTokenVerifier;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.SecurityConstraint;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.valves.ValveBase;

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

	public void setSecret(String secret) {
		this.secret = secret;
	}

	public void setBase64(boolean isBase64) {
		this.isBase64 = isBase64;
	}
}
