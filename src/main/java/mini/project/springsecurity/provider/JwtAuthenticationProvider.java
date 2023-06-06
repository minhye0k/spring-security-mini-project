package mini.project.springsecurity.provider;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import mini.project.springsecurity.exception.JwtInvalidException;
import mini.project.springsecurity.tokens.JwtAuthenticationToken;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Component
public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final String KEY_ROLES = "roles";
    private final byte[] secretKeyByte;

    public JwtAuthenticationProvider(@Value("${jwt.secret-key}") String secretKey) {
        this.secretKeyByte = secretKey.getBytes();
    }

    private Collection<? extends GrantedAuthority> createGrantedAuthorities(Claims claims) {
        List<String> roles = (List) claims.get(KEY_ROLES);
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        for (String role : roles) {
            grantedAuthorities.add(() -> role);
        }
        return grantedAuthorities;
    }


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Claims claims;
        try {
            claims = Jwts.parser().setSigningKey(secretKeyByte).parseClaimsJws(((JwtAuthenticationToken) authentication).getJwt()).getBody();
        } catch (SignatureException signatureException) {
            throw new JwtInvalidException("signature key is different", signatureException);
        } catch (ExpiredJwtException expiredJwtException) {
            throw new JwtInvalidException("expired token", expiredJwtException);
        } catch (MalformedJwtException malformedJwtException) {
            throw new JwtInvalidException("malformed token", malformedJwtException);
        } catch (IllegalArgumentException illegalArgumentException) {
            throw new JwtInvalidException("using illegal argument like null", illegalArgumentException);
        }
        return new JwtAuthenticationToken(claims.getSubject(), "", createGrantedAuthorities(claims));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
