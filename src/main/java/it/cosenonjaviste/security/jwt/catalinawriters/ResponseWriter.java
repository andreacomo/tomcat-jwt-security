package it.cosenonjaviste.security.jwt.catalinawriters;

import org.apache.catalina.connector.Response;

import java.io.IOException;

/**
 * Abstract class for catalina response writing. 
 * Supported media type are json and xml. Html is default
 * 
 * @author acomo
 *
 */
public abstract class ResponseWriter {

	static final String APPLICATION_XML = "application/xml";
	
	static final String APPLICATION_JSON = "application/json";
	
	/**
	 * Create a new {@link ResponseWriter} instance based on provided mimetype.
	 * 
	 * Supported mimetype are:
	 * <ul>
	 * <li>application/json</li>
	 * <li>application/xml</li>
	 * <li>text/html is default</li>
	 * </ul>
	 * 
	 * @param mimeType accepted mimetype from client
	 * @return a new {@link ResponseWriter} instance
	 */
	public static ResponseWriter get(String mimeType) {
		String nullSafeMimeType = mimeType != null ? mimeType : "";
		if (nullSafeMimeType.contains(APPLICATION_JSON)) {
			return new JsonResponseWriter();
		} else if (nullSafeMimeType.contains(APPLICATION_XML)) {
			return new XmlResponseWriter();
		} else {
			return new HtmlResponseWriter();
		}
	}
	
	/**
	 * Write body values to response with provided status code. Body serialization depends on concrete class
	 * 
	 * @param response HTTP response object
	 * @param statusCode response status code to set
	 * @param body response body
	 * @throws IOException exception on writing response data to response object
	 */
	public abstract void write(Response response, int statusCode, Object body) throws IOException;
}
