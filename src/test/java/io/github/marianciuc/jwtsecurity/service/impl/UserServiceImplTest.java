package io.github.marianciuc.jwtsecurity.service.impl;

import io.github.marianciuc.jwtsecurity.entity.JwtUser;
import io.github.marianciuc.jwtsecurity.enums.TokenType;
import io.github.marianciuc.jwtsecurity.service.JwtUserDetails;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class UserServiceImplTest {

    private static UserServiceImpl userService;
    private static JwtUserDetails mockUser;

    @BeforeEach
    public void setUp() {
        userService = createUserService();
        mockUser = createMockUser();
    }

    private static UserServiceImpl createUserService() {
        return new UserServiceImpl();
    }

    private static JwtUserDetails createMockUser() {
        return new JwtUser(
                "username",
                "ROLE_USER",
                UUID.randomUUID(),
                TokenType.ACCESS_TOKEN
        );
    }

    @Test
    void shouldSetUserAuthentication() {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);

        userService.setUserAuthentication(mockUser, mockRequest);

        assertInstanceOf(UsernamePasswordAuthenticationToken.class,
                SecurityContextHolder.getContext().getAuthentication()
        );
        assertEquals(mockUser, SecurityContextHolder.getContext().getAuthentication().getPrincipal());
    }

    @Test
    void shouldGetUserSuccessfully() {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(
                        mockUser,
                        null,
                        mockUser.getAuthorities()
                );

        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        JwtUserDetails actualUserDetails = userService.getUser();
        assertEquals(mockUser, actualUserDetails);
    }

    @Test
    void shouldThrowExceptionWhenGetUserWithNoAuthentication() {
        SecurityContextHolder.getContext().setAuthentication(null);
        assertThrows(AuthenticationServiceException.class, userService::getUser);
    }

    @Test
    void shouldThrowExceptionWhenGetUserWithAuthenticationNotInstanceOfJwtUserDetails() {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(
                        "Not JwtUserDetails instance",
                        null,
                        Collections.emptyList()
                );

        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        assertThrows(AuthenticationServiceException.class, userService::getUser);
    }
}
