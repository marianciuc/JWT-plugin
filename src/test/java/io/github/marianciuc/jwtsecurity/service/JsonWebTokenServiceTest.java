package io.github.marianciuc.jwtsecurity.service;

import io.github.marianciuc.jwtsecurity.enums.TokenType;
import io.github.marianciuc.jwtsecurity.exceptions.JwtSecurityException;
import io.github.marianciuc.jwtsecurity.service.impl.JsonWebTokenServiceImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Base64;
import java.util.UUID;

public class JsonWebTokenServiceTest {

    private final static String SUBJECT = "SUBJECT";
    private final static String ROLE = "ROLE";
    private static final String ROLE_SERVICE = "ROLE_SERVICE";
    private static final Long accessExpiration = 3600000L;
    private static final Long refreshExpiration = 3600000L;
    private static final String SERVICE_NAME = "SERVICE_NAME";

    private JsonWebTokenServiceImpl service;

    @BeforeEach
    public void setUp() {
        UUID uuid = UUID.randomUUID();
        byte[] bytes = uuid.toString().getBytes();
        String secret = Base64.getEncoder().encodeToString(bytes);
        service = new JsonWebTokenServiceImpl(SERVICE_NAME, secret, accessExpiration, refreshExpiration);
    }

    /**
     * This method is used to test the generation of an access token.
     * It creates a new instance of UserDetails using the provided subject and role.
     * Then, it generates an access token based on the user details.
     * Finally, it asserts that the generated token is not null and not empty.
     */
    @Test
    public void testGenerateAccessToken() {
        JwtUserDetails userDetails = service.create(SUBJECT, ROLE, UUID.randomUUID(), TokenType.ACCESS_TOKEN);
        String token = service.generateAccessToken(userDetails);
        Assertions.assertNotNull(token);
        Assertions.assertFalse(token.isEmpty());
    }

    /**
     * This method is used to test the generation of a refresh token.
     * It creates a new instance of UserDetails using the provided subject and role.
     * Then, it generates a refresh token based on the user details.
     * Finally, it asserts that the generated token is not null and not empty.
     */
    @Test
    public void testGenerateRefreshToken() {
        JwtUserDetails userDetails = service.create(SUBJECT, ROLE, UUID.randomUUID(), TokenType.REFRESH_TOKEN);
        String token = service.generateRefreshToken(userDetails);
        Assertions.assertNotNull(token);
        Assertions.assertFalse(token.isEmpty());
    }

    @Test
    public void testServiceToken() {
        String token = service.generateServiceToken();
        Assertions.assertNotNull(token);
        Assertions.assertFalse(token.isEmpty());
        UserDetails userDetails = service.parseAccessToken(token);
        Assertions.assertEquals(ROLE_SERVICE, userDetails.getUsername());
        Assertions.assertEquals(ROLE_SERVICE, userDetails.getAuthorities().iterator().next().getAuthority());
    }

    @Test
    public void testParseAccessToken() {
        JwtUserDetails userDetails = service.create(SUBJECT, ROLE, UUID.randomUUID(), TokenType.ACCESS_TOKEN);
        String token = service.generateAccessToken(userDetails);
        UserDetails parsedDetails = service.parseAccessToken(token);
        Assertions.assertEquals(userDetails.getUsername(), parsedDetails.getUsername());
    }

    @Test
    public void testParseRefreshToken() {
        JwtUserDetails userDetails = service.create(SUBJECT, ROLE, UUID.randomUUID(), TokenType.REFRESH_TOKEN);
        String token = service.generateRefreshToken(userDetails);
        UserDetails parsedDetails = service.parseRefreshToken(token);
        Assertions.assertEquals(userDetails.getUsername(), parsedDetails.getUsername());
    }

    @Test
    public void testParseAccessTokenWithRefreshToken() {
        JwtUserDetails userDetails = service.create(SUBJECT, ROLE, UUID.randomUUID(), TokenType.REFRESH_TOKEN);
        String token = service.generateRefreshToken(userDetails);
        Assertions.assertThrows(JwtSecurityException.class, () ->
                service.parseAccessToken(token)
        );
    }

    @Test
    public void testParseRefreshTokenWithAccessToken() {
        JwtUserDetails userDetails = service.create(SUBJECT, ROLE, UUID.randomUUID(), TokenType.ACCESS_TOKEN);
        String token = service.generateAccessToken(userDetails);
        Assertions.assertThrows(JwtSecurityException.class, () ->
                service.parseRefreshToken(token)
        );
    }

    @AfterEach
    public void tearDown() {
        service = null;
    }
}