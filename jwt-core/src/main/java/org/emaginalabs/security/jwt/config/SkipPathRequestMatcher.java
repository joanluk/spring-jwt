package org.emaginalabs.security.jwt.config;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;


/**
 * SkipPathRequestMatcher
 */
public class SkipPathRequestMatcher implements RequestMatcher {
    private final OrRequestMatcher matchers;
    private final RequestMatcher processingMatcher;

    public SkipPathRequestMatcher(List<String> pathsToSkip, String processingPath) {
        Assert.notNull(pathsToSkip, "path to skip is null");
        List<RequestMatcher> requestMatchers = new ArrayList<RequestMatcher>();

        for (String pathToSkip : pathsToSkip) {
            requestMatchers.add(new AntPathRequestMatcher(pathToSkip));
        }
        matchers = new OrRequestMatcher(requestMatchers);
        processingMatcher = new AntPathRequestMatcher(processingPath);
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        if (matchers.matches(request)) {
            return false;
        }
        return processingMatcher.matches(request);
    }
}