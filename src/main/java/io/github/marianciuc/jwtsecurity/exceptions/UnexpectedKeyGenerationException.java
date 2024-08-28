package io.github.marianciuc.jwtsecurity.exceptions;

/**
 * UnexpectedKeyGenerationException is an exception that is thrown when there is an unexpected error during key generation.
 *
 * @author Vladimir Marianciuc
 * @version 1.0
 */
public class UnexpectedKeyGenerationException extends RuntimeException {
    public UnexpectedKeyGenerationException(String message) {
        super(message);
    }
}
