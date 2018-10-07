package org.emaginalabs.security.jwt.filter;


import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;
import org.emaginalabs.security.jwt.config.JwtSettings;
import org.emaginalabs.security.jwt.token.model.JwtToken;
import org.emaginalabs.security.jwt.token.provider.JwtTokenProvider;
import org.emaginalabs.security.jwt.token.provider.TokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.*;


/**
 * Authentication entry point in the system
 */
@EqualsAndHashCode(callSuper = true)
@Slf4j
public class JwtLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private String credentialsCharset = "UTF-8";

    public static final String AUTHENTICATION_HEADER_NAME = "Authorization";
    private static final String TOKEN_RESPONSE_HEADER = "header";
    private static final String TOKEN_RESPONSE_PAYLOAD = "payload";
    private static final String DEFAULT_SEPARATOR = ",";
    @Autowired(required = false)
    private ObjectMapper mapper = new ObjectMapper();

    private final JwtSettings jwtSettings;

    private List<String> tokenResponseModes;

    private String separatorResponseMode = DEFAULT_SEPARATOR;

    private final TokenProvider tokenProvider;

    private AuthenticationManager authenticationMan;

    public JwtLoginProcessingFilter(String url, AuthenticationManager authManager, TokenProvider tokenProvider,
                                    JwtSettings jwtSettings) {
        super(new AntPathRequestMatcher(url));
        setAuthenticationManager(authManager);
        this.tokenProvider = tokenProvider;
        this.jwtSettings = jwtSettings;
        initTokenResponse();
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String header = request.getHeader(AUTHENTICATION_HEADER_NAME);

        if (header != null && header.startsWith("Basic ")) {

            String[] tokens = extractAndDecodeHeader(header, request);
            assert tokens.length == 2;

            String username = tokens[0];

            log.debug("Basic Authentication Authorization header found for user '{0}'",
                    username);

            // Verify if the correctness of login details.
            // If correct, the successfulAuthentication() method is executed.
            return getAuthenticationManager().authenticate(
                    new UsernamePasswordAuthenticationToken(
                            username,
                            tokens[1],
                            new ArrayList<GrantedAuthority>()
                    )
            );
        }
        throw new AuthenticationServiceException("Username or Password not provided");
    }


    @Override
    protected void successfulAuthentication(HttpServletRequest req, HttpServletResponse res, FilterChain chain,
                                            Authentication auth) throws IOException, ServletException {

        // Pass authenticated user data to the jwtTokenAuthenticationService in order to add a JWT to the http response.
        addAuthentication(res, auth);
        clearAuthenticationAttributes(req);
    }

    /**
     * Decodes the header into a username and password.
     *
     * @throws BadCredentialsException if the Basic header is not present or is not valid
     *                                 Base64
     */
    private String[] extractAndDecodeHeader(String header, HttpServletRequest request)
            throws IOException {

        byte[] base64Token = header.substring(6).getBytes("UTF-8");
        byte[] decoded;
        try {
            decoded = Base64.decode(base64Token);
        } catch (IllegalArgumentException e) {
            throw new BadCredentialsException(
                    "Failed to decode basic authentication token");
        }

        String token = new String(decoded, getCredentialsCharset(request));

        int delim = token.indexOf(":");

        if (delim == -1) {
            throw new BadCredentialsException("Invalid basic authentication token");
        }
        return new String[]{token.substring(0, delim), token.substring(delim + 1)};
    }

    private String getCredentialsCharset(HttpServletRequest httpRequest) {
        return this.credentialsCharset;
    }

    /**
     * Removes temporary authentication-related data which may have been stored
     * in the session during the authentication process..
     */
    private void clearAuthenticationAttributes(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return;
        }

        session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
    }


    /**
     * When a user successfully logs into the application, create a token for that user.
     * The token is included in the header or payload depending on the zero configuration property app.env.security.jwt.token.response.
     * By default if not reported will be included in both the header and payload
     *
     * @param response An http response that will be filled with an 'Authentication' header containing the token.
     */
    private void addAuthentication(HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        JwtToken accessToken = tokenProvider.createToken(authentication);
        for (String tokenResponseMode : tokenResponseModes) {
            if (TOKEN_RESPONSE_HEADER.equalsIgnoreCase(tokenResponseMode)) {
                response.addHeader(JwtTokenProvider.AUTHENTICATION_HEADER_NAME,
                        JwtTokenProvider.TOKEN_PREFIX + " " + accessToken.getToken());
            }
            if (TOKEN_RESPONSE_PAYLOAD.equalsIgnoreCase(tokenResponseMode)) {
                Map<String, String> tokenMap = new HashMap<String, String>();
                tokenMap.put("token", accessToken.getToken());

                response.setStatus(HttpStatus.OK.value());
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                mapper.writeValue(response.getWriter(), tokenMap);
            }
        }
    }

    public void initTokenResponse() {
        tokenResponseModes = Arrays.asList(jwtSettings.getTokenResponse().split(separatorResponseMode));
        Assert.isTrue(isValidTokenResponseMode(tokenResponseModes),
                "No place to return token could be found or no valid values. Please indicate some value of the allowed, " +
                        "'header' or 'payload' in the property app.env.security.jwt.token.response.");


    }

    private boolean isValidTokenResponseMode(List<String> tokenResponseModes) {
        if (tokenResponseModes.isEmpty()) {
            return false;
        } else {
            for (String responseMode : tokenResponseModes) {
                if (!responseMode.equalsIgnoreCase(TOKEN_RESPONSE_HEADER) &&
                        !responseMode.equalsIgnoreCase(TOKEN_RESPONSE_PAYLOAD)) {
                    return false;
                }
            }
        }
        log.debug("Used this values as responde mode token, {0}", tokenResponseModes.toString());
        return true;
    }

    public void setSeparatorResponseMode(String separatorResponseMode) {
        this.separatorResponseMode = separatorResponseMode;
    }
}