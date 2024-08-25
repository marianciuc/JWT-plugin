package io.github.marianciuc.jwtplugin.exceptions;

public class KeyDecodingException extends RuntimeException {
    public KeyDecodingException(String message) {
        super(message);
    }
}