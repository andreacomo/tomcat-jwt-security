package it.cosenonjaviste.security.jwt.catalinawriters;

import org.junit.Test;

import static org.junit.Assert.assertTrue;

/**
 * Created by acomo on 18/06/18.
 */
public class ResponseWriterTest {

    @Test
    public void shouldReturnJsonWriter() {
        assertTrue(ResponseWriter.get("application/json") instanceof JsonResponseWriter);
        assertTrue(ResponseWriter.get("application/json, text/plain, */*") instanceof JsonResponseWriter);
    }

    @Test
    public void shouldReturnXmlWriter() {
        assertTrue(ResponseWriter.get("application/xml") instanceof XmlResponseWriter);
        assertTrue(ResponseWriter.get("application/xml, text/plain, */*") instanceof XmlResponseWriter);
    }

    @Test
    public void shouldReturnHtmlWriter() {
        assertTrue(ResponseWriter.get("unknown/mimetype") instanceof HtmlResponseWriter);
        assertTrue(ResponseWriter.get("*/*") instanceof HtmlResponseWriter);
    }
}