package it.cosenonjaviste.security.jwt.catalinawriters;

import org.apache.catalina.connector.Response;

import java.io.IOException;

/**
 * Standard HTML response writer
 * 
 * @author acomo
 *
 */
class HtmlResponseWriter extends ResponseWriter {

	@Override
	public void write(Response response, int statusCode, Object body) throws IOException {
		response.sendError(statusCode, body.toString());
	}

}
