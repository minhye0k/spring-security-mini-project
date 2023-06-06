package mini.project.springsecurity.tokens;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import javax.security.auth.Subject;
import java.util.Collection;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {
    private String jwt;
    private Object principal;

    private Object credentials;

    public JwtAuthenticationToken(String jwt){
        super(null);
        this.jwt = jwt;
        setAuthenticated(false);
    }

    public JwtAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        setAuthenticated(true);
    }


    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    public String getJwt() {
        return jwt;
    }

}
