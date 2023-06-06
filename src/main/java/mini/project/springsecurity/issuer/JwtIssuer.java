package mini.project.springsecurity.issuer;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import mini.project.springsecurity.exception.JwtInvalidException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.management.ObjectName;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Date;

@Component
public class JwtIssuer {
    private final int SECOND = 1000;
    private final int MINUTE = 60 * SECOND;
    private final String ROLES = "roles";

    private final byte[] secretKeyBytes;
    private final byte[] refreshSecretKeyBytes;
    private int expireMin;
    private int refreshExpireMin;

    public JwtIssuer(@Value("${jwt.secret-key}") String secretKey,
                     @Value("${jwt.refresh-secret-key}") String refreshSecretKey,
                     @Value("${jwt.expire-min}") int expireMin,
                     @Value("${jwt.refresh-expire-min}") int refreshExpireMin) {
        this.secretKeyBytes = secretKey.getBytes();
        this.refreshSecretKeyBytes = refreshSecretKey.getBytes();
        this.expireMin = expireMin;
        this.refreshExpireMin = refreshExpireMin;
    }

    private String makeToken(Long userSeq, String authority, byte[] secretKeyBytes, int expireMin) {
        Date now = new Date();
        Claims claims = Jwts.claims().setSubject(userSeq.toString());
        claims.put(ROLES, Collections.singleton(authority));
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + MINUTE * expireMin))
                .signWith(SignatureAlgorithm.HS256, secretKeyBytes)
                .compact();
    }

    public String issueAccessToken(Long userSeq, String authority) {
        return makeToken(userSeq, authority, secretKeyBytes, expireMin);
    }

    public String issueRefreshToken(Long userSeq, String authority){
        return makeToken(userSeq, authority, refreshSecretKeyBytes, refreshExpireMin);
    }

    public Claims parseClaimsFromRefreshToken(String jwt) {
        Claims claims;
        try {
            claims = Jwts.parser().setSigningKey(refreshSecretKeyBytes).parseClaimsJws(jwt).getBody();
        } catch (SignatureException signatureException) {
            throw new JwtInvalidException("signature key is different", signatureException);
        } catch (ExpiredJwtException expiredJwtException) {
            throw new JwtInvalidException("expired token", expiredJwtException);
        } catch (MalformedJwtException malformedJwtException) {
            throw new JwtInvalidException("malformed token", malformedJwtException);
        } catch (IllegalArgumentException illegalArgumentException) {
            throw new JwtInvalidException("using illegal argument like null", illegalArgumentException);
        }
        return claims;
    }
}
