package io.github.marianciuc.jwtplugin.exceptions;

public class JsonWebTokenExpiredException extends RuntimeException {
    public JsonWebTokenExpiredException(String message, String exception) {
        super(message);
    }
}
