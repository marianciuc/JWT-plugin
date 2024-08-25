package io.github.marianciuc.jwtsecurity.exceptions;

public class JsonWebTokenExpiredException extends RuntimeException {
    public JsonWebTokenExpiredException(String message, String exception) {
        super(message);
    }
}
