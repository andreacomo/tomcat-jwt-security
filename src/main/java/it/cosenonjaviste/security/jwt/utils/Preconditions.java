package it.cosenonjaviste.security.jwt.utils;

import it.cosenonjaviste.security.jwt.exceptions.ValveInitializationException;

public class Preconditions {

    public static void checkState(boolean expression, String errorMessage) {
        if (!expression) {
            throw new IllegalStateException(errorMessage);
        }
    }

    public static void checkArgument(boolean expression, String errorMessage) {
        if (!expression) {
            throw new IllegalArgumentException(errorMessage);
        }
    }

    public static void checkValveInit(boolean expression, String errorMessage) {
        if (!expression) {
            throw new ValveInitializationException(errorMessage);
        }
    }
}
