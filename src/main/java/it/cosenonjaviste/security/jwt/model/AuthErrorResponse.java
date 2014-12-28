package it.cosenonjaviste.security.jwt.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "AuthError")
@XmlAccessorType(XmlAccessType.FIELD)
public class AuthErrorResponse {

	private String message;

	public AuthErrorResponse() {

	}
	
	public AuthErrorResponse(String message) {
		super();
		this.message = message;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	@Override
	public String toString() {
		return message;
	}
	
}
