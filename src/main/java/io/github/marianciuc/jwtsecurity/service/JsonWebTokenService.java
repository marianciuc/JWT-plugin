package io.github.marianciuc.jwtsecurity.service;

import io.github.marianciuc.jwtsecurity.enums.TokenType;

import java.util.UUID;

/**
 * This interface is an extension of Spring Security's UserDetails interface customized for JSON Web Token (JWT)
 * authentication. It provides several methods to obtain properties related to the user such as role, token type,
 * whether the user is a service, and the unique user identification.
 * @version 1.0
 * @author Vladimir Marianciuc
 */
public interface JsonWebTokenService {
    JwtUserDetails create(String subject, String role, UUID id, TokenType tokenType);
    String generateAccessToken(JwtUserDetails userDetails);
    String generateRefreshToken(JwtUserDetails userDetails);
    String generateServiceToken();
    JwtUserDetails parseRefreshToken(String token);
    JwtUserDetails parseAccessToken(String token);
}
