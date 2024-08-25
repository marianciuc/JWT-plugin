package io.github.marianciuc.jwtsecurity.service;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.userdetails.UserDetails;


import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class JsonWebTokenFilterTest {

    @Mock
    JsonWebTokenService jsonWebTokenService;

    @InjectMocks
    JsonWebTokenFilter jsonWebTokenFilter;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.initMocks(this);
    }

    /**
     * Test to verify that the doFilterInternal method of the JsonWebTokenFilter class
     * calls the JsonWebTokenService's parseAccessToken method with the correct token
     * and sets the authentication based on the user details retrieved.
     *
     * @throws Exception if an error occurs during the test execution
     */
    @Test
    public void doFilterInternal_withBearerAuthorizationHeader_callsJsonWebTokenServiceAndSetsAuthentication() throws Exception {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        FilterChain chain = Mockito.mock(FilterChain.class);

        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer token");
        UserDetails userDetails = Mockito.mock(UserDetails.class);
        when(jsonWebTokenService.parseAccessToken(any(String.class))).thenReturn(userDetails);

        jsonWebTokenFilter.doFilterInternal(request, response, chain);
        verify(jsonWebTokenService).parseAccessToken(eq("token"));
        verify(chain).doFilter(request, response);
    }

    /**
     * This method is a unit test that verifies that when the `doFilterInternal` method of the `JsonWebTokenFilter` class
     * is called without a Bearer authorization header, it does not call the `JsonWebTokenService`.
     * Instead, it simply invokes the `doFilter` method of the provided `FilterChain` object.
     *
     * @throws Exception if an error occurs during the test execution
     */
    @Test
    public void doFilterInternal_withoutBearerAuthorizationHeader_doesNotCallJsonWebTokenService() throws Exception {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        FilterChain chain = Mockito.mock(FilterChain.class);

        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(null);

        jsonWebTokenFilter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(request, response);
    }

    /**
     * This method is a unit test that verifies that when the `doFilterInternal` method of the `JsonWebTokenFilter` class
     * is called with a non-Bearer authorization header, it does not call the `JsonWebTokenService`.
     * Instead, it simply invokes the `doFilter` method of the provided `FilterChain` object.
     *
     * @throws Exception if an error occurs during the test execution
     */
    @Test
    public void doFilterInternal_withNonBearerAuthorizationHeader_doesNotCallJsonWebTokenService() throws Exception {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        FilterChain chain = Mockito.mock(FilterChain.class);

        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("NonBearerToken");

        jsonWebTokenFilter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(request, response);
    }
}