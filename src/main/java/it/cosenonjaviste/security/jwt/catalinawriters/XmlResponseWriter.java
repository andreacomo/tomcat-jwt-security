package it.cosenonjaviste.security.jwt.catalinawriters;

import java.io.IOException;

import javax.xml.bind.JAXB;

import org.apache.catalina.connector.Response;

/**
 * XML response writer, based on JAXB serializer
 * 
 * @author acomo
 *
 */
class XmlResponseWriter extends ResponseWriter {

	@Override
	public void write(Response response, int statusCode, Object body)
			throws IOException {
		
		response.setStatus(statusCode);
		response.setContentType(APPLICATION_XML);
		JAXB.marshal(body, response.getWriter());
		
	}

}
