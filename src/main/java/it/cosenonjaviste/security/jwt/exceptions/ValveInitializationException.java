package it.cosenonjaviste.security.jwt.exceptions;

public class ValveInitializationException extends RuntimeException {

    public ValveInitializationException(String message) {
        super(message);
    }

    public ValveInitializationException(String message, Throwable cause) {
        super(message, cause);
    }
}
