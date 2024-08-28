package io.github.marianciuc.jwtsecurity.service;

import io.github.marianciuc.jwtsecurity.entity.JwtUser;
import io.github.marianciuc.jwtsecurity.enums.TokenType;
import io.github.marianciuc.jwtsecurity.filters.JsonWebTokenFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpHeaders;


import java.io.IOException;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class JsonWebTokenFilterTest {

    @Mock
    JsonWebTokenService jsonWebTokenService;

    @Mock
    private UserService userService;

    JsonWebTokenFilter jsonWebTokenFilter;

    private HttpServletRequest request;
    private HttpServletResponse response;
    private FilterChain chain;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.initMocks(this);
        jsonWebTokenFilter = new JsonWebTokenFilter(jsonWebTokenService, userService);
        request = Mockito.mock(HttpServletRequest.class);
        response = Mockito.mock(HttpServletResponse.class);
        chain = Mockito.mock(FilterChain.class);
    }

    @Test
    public void testDoFilterInternal() throws ServletException, IOException {
        final String token = "token";
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer " + token);
        JwtUser userDetails = new JwtUser("user", "pass", UUID.randomUUID(), TokenType.ACCESS_TOKEN);
        when(jsonWebTokenService.parseAccessToken(token)).thenReturn(userDetails);

        jsonWebTokenFilter.doFilterInternal(request, response, chain);

        verify(jsonWebTokenService).parseAccessToken(token);
        verify(chain).doFilter(request, response);
    }

    @Test
    public void testDoFilterInternalWithNoToken() throws ServletException, IOException {
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(null);

        jsonWebTokenFilter.doFilterInternal(request, response, chain);

        verify(jsonWebTokenService, never()).parseAccessToken(any(String.class));
        verify(chain).doFilter(request, response);
    }
}
