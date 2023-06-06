package mini.project.springsecurity.utils.extractor;

import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

public class AuthorizationExtractor {
    private static final String BEARER_TYPE = "Bearer ";

    public static String extractFromRequest(final HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_TYPE)) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public static String extractFromTokenIncludingBearer(final String jwt) {
        if (StringUtils.hasText(jwt) && jwt.startsWith(BEARER_TYPE)) {
            return jwt.substring(7);
        }
        return null;
    }
}
