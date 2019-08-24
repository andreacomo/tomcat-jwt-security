package it.cosenonjaviste.security.jwt.catalinawriters;

import java.io.IOException;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.catalina.connector.Response;

/**
 * JSON response writer, based on Jackson json serializer
 * 
 * @author acomo
 *
 */
class JsonResponseWriter extends ResponseWriter {

	@Override
	public void write(Response response, int statusCode, Object body)
			throws IOException {
		
		response.setStatus(statusCode);
		response.setContentType(APPLICATION_JSON);
		ObjectMapper objectMapper = new ObjectMapper();
		objectMapper.writeValue(response.getWriter(), body);
	}

}
