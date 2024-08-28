package io.github.marianciuc.jwtsecurity.filters;

import io.github.marianciuc.jwtsecurity.service.JsonWebTokenService;
import io.github.marianciuc.jwtsecurity.service.JwtUserDetails;
import io.github.marianciuc.jwtsecurity.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


/**
 * The `JsonWebTokenFilter` class is a filter that is responsible for intercepting incoming requests,
 * extracting the JSON Web Token (JWT) from the `Authorization` header, and authenticating the user
 * based on the extracted token.
 * @author Vladimir Marianciuc
 * @version 1.0
 */
public class JsonWebTokenFilter extends OncePerRequestFilter {

    private final static String BEARER_STR = "Bearer ";
    private final JsonWebTokenService jsonWebTokenService;
    private final UserService userService;

    public JsonWebTokenFilter(JsonWebTokenService jsonWebTokenService, UserService userService) {
        this.jsonWebTokenService = jsonWebTokenService;
        this.userService = userService;
    }

    @Override
    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);


        if (authHeader != null && authHeader.startsWith(BEARER_STR)) {
            String jwt = authHeader.substring(BEARER_STR.length());
            JwtUserDetails userDetails = jsonWebTokenService.parseAccessToken(jwt);
            userService.setUserAuthentication(userDetails, request);
        }

        filterChain.doFilter(request, response);
    }
}
