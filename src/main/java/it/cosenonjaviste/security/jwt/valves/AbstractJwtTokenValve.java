package it.cosenonjaviste.security.jwt.valves;

import it.cosenonjaviste.security.jwt.catalinawriters.ResponseWriter;
import it.cosenonjaviste.security.jwt.model.AuthErrorResponse;
import it.cosenonjaviste.security.jwt.model.JwtAdapter;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.valves.ValveBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Template class for performing a JWT authentication on requester resource, if has securiy constraints associated.
 * 
 * @author acomo
 *
 */
public abstract class AbstractJwtTokenValve extends ValveBase {

	private static final Log LOG = LogFactory.getLog(AbstractJwtTokenValve.class);

	protected String customUserIdClaim;

	protected String customRolesClaim;

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

	protected abstract void handleAuthentication(Request request, Response response)
			throws IOException, ServletException;

	protected void authenticateRequest(Request request, JwtAdapter jwt) {
		GenericPrincipal principal = new GenericPrincipal(jwt.getUserId(), null, jwt.getRoles());
		request.setUserPrincipal(principal);
		request.setAuthType("TOKEN");
	}

	protected void sendUnauthorizedError(Request request, Response response, String message) throws IOException {
		ResponseWriter.get(request.getHeader("accept")).write(response, HttpServletResponse.SC_UNAUTHORIZED, new AuthErrorResponse(message));
	}

	public void setCustomUserIdClaim(String customUserIdClaim) {
		this.customUserIdClaim = customUserIdClaim;
	}

	public void setCustomRolesClaim(String customRolesClaim) {
		this.customRolesClaim = customRolesClaim;
	}
}