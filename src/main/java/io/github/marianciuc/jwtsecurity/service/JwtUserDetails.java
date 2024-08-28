package io.github.marianciuc.jwtsecurity.service;

import io.github.marianciuc.jwtsecurity.enums.TokenType;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.UUID;

/**
 * This interface extends UserDetails with some additional JWT-specific methods used for user authentication and user data retrieval.
 * @version 1.0
 * @author Vladimir Marianciuc
 */
public interface JwtUserDetails extends UserDetails {
    String getRole();
    TokenType getType();
    boolean isService();
    UUID getId();
}
