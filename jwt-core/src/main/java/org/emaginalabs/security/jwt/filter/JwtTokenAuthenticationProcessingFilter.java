package org.emaginalabs.security.jwt.filter;


import lombok.extern.slf4j.Slf4j;
import org.emaginalabs.security.jwt.JwtTokenAuthentication;
import org.emaginalabs.security.jwt.token.provider.JwtTokenProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


@Slf4j
public class JwtTokenAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private final AuthenticationFailureHandler failureHandler;


    public JwtTokenAuthenticationProcessingFilter(RequestMatcher matcher, AuthenticationFailureHandler failureHandler) {
        super("/**");
        this.failureHandler = failureHandler;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String tokenPayload = request.getHeader(JwtTokenProvider.AUTHENTICATION_HEADER_NAME);
        return getAuthenticationManager().authenticate(new JwtTokenAuthentication(tokenPayload));
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authResult);

        SecurityContextHolder.setContext(context);
        chain.doFilter(request, response);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException failed) throws IOException, ServletException {
        SecurityContextHolder.clearContext();
        failureHandler.onAuthenticationFailure(request, response, failed);

    }

    /**
     * Indicates whether this filter should attempt to process a login request for the
     * current invocation.
     * <p>
     * It strips any parameters from the "path" section of the request URL (such as the
     * jsessionid parameter in <em>http://host/myapp/index.html;jsessionid=blah</em>)
     * before matching against the <code>filterProcessesUrl</code> property.
     * <p>
     * Subclasses may override for special requirements, such as Tapestry integration.
     *
     * @param request  request
     * @param response response
     * @return <code>   true</code> if the filter should attempt authentication,
     * <code>false</code> otherwise.
     */
    @Override
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        String token = request.getHeader(JwtTokenProvider.AUTHENTICATION_HEADER_NAME);

        if (token == null || !token.startsWith("Bearer ")) {
            return false;
        }
        return super.requiresAuthentication(request, response);
    }


}