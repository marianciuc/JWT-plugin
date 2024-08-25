package io.github.marianciuc.jwtsecurity.service;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


/**
 * The `JsonWebTokenFilter` class is a filter that is responsible for intercepting incoming requests,
 * extracting the JSON Web Token (JWT) from the `Authorization` header, and authenticating the user
 * based on the extracted token.
 */
public class JsonWebTokenFilter extends OncePerRequestFilter {

    private final static String BEARER_STR = "Bearer ";
    private final JsonWebTokenService jsonWebTokenService;

    public JsonWebTokenFilter(JsonWebTokenService jsonWebTokenService) {
        this.jsonWebTokenService = jsonWebTokenService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);


        if (authHeader != null && authHeader.startsWith(BEARER_STR)) {
            String jwt = authHeader.substring(BEARER_STR.length());
            UserDetails userDetails = jsonWebTokenService.parseAccessToken(jwt);
            setUserAuthentication(userDetails, request);
        }

        filterChain.doFilter(request, response);
    }

    private void setUserAuthentication(UserDetails user, HttpServletRequest request) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                user, null, user.getAuthorities());
        usernamePasswordAuthenticationToken
                .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
    }

}
