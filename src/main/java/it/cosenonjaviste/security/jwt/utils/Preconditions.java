package it.cosenonjaviste.security.jwt.utils;

public class Preconditions {

    public static void checkState(boolean expression, String errorMessage) {
        if (!expression) {
            throw new IllegalStateException(errorMessage);
        }
    }
}
