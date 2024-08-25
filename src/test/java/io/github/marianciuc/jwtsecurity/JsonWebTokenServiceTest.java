package io.github.marianciuc.jwtsecurity;

import io.github.marianciuc.jwtsecurity.exceptions.JwtSecurityException;
import io.github.marianciuc.jwtsecurity.service.JsonWebTokenService;
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
    private final static String SERVICE = "SERVICE";
    private static final String ROLE_SERVICE = "ROLE_SERVICE";
    private static final Long accessExpiration = 3600000L;
    private static final Long refreshExpiration = 3600000L;
    private JsonWebTokenService service;

    @BeforeEach
    public void setUp() {
        UUID uuid = UUID.randomUUID();
        byte[] bytes = uuid.toString().getBytes();
        String secret = Base64.getEncoder().encodeToString(bytes);
        service = new JsonWebTokenService(secret, accessExpiration, refreshExpiration);
    }

    @Test
    public void testGenerateAccessToken() {
        UserDetails userDetails = service.create(SUBJECT, ROLE);
        String token = service.generateAccessToken(userDetails);
        Assertions.assertNotNull(token);
        Assertions.assertFalse(token.isEmpty());
    }

    @Test
    public void testGenerateRefreshToken() {
        UserDetails userDetails = service.create(SUBJECT, ROLE);
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
        Assertions.assertEquals(SERVICE, userDetails.getUsername());
        Assertions.assertEquals(ROLE_SERVICE, userDetails.getAuthorities().iterator().next().getAuthority());
    }

    @Test
    public void testParseAccessToken() {
        UserDetails userDetails = service.create(SUBJECT, ROLE);
        String token = service.generateAccessToken(userDetails);
        UserDetails parsedDetails = service.parseAccessToken(token);
        Assertions.assertEquals(userDetails.getUsername(), parsedDetails.getUsername());
    }

    @Test
    public void testParseRefreshToken() {
        UserDetails userDetails = service.create(SUBJECT, ROLE);
        String token = service.generateRefreshToken(userDetails);
        UserDetails parsedDetails = service.parseRefreshToken(token);
        Assertions.assertEquals(userDetails.getUsername(), parsedDetails.getUsername());
    }

    @Test
    public void testParseAccessTokenWithRefreshToken() {
        UserDetails userDetails = service.create(SUBJECT, ROLE);
        String token = service.generateRefreshToken(userDetails);
        Assertions.assertThrows(JwtSecurityException.class, () -> {
            service.parseAccessToken(token);
        });
    }

    @Test
    public void testParseRefreshTokenWithAccessToken() {
        UserDetails userDetails = service.create(SUBJECT, ROLE);
        String token = service.generateAccessToken(userDetails);
        Assertions.assertThrows(JwtSecurityException.class, () -> {
            service.parseRefreshToken(token);
        });
    }

    @AfterEach
    public void tearDown() {
        service = null;
    }
}