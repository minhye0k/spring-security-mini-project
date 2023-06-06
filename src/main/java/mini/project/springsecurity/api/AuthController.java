package mini.project.springsecurity.api;

import lombok.RequiredArgsConstructor;
import mini.project.springsecurity.dto.request.SignInRequest;
import mini.project.springsecurity.dto.request.SignUpRequest;
import mini.project.springsecurity.dto.response.SignInResponse;
import mini.project.springsecurity.dto.response.SignUpResponse;
import mini.project.springsecurity.issuer.JwtIssuer;
import mini.project.springsecurity.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.REFRESH_TOKEN;

@RestController
@RequiredArgsConstructor
@RequestMapping("auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("sign-in")
    public ResponseEntity<SignInResponse> signIn(@RequestBody SignInRequest signInRequest) {
        return ResponseEntity.ok(authService.signIn(signInRequest));
    }

    @PostMapping("sign-up")
    public ResponseEntity<SignUpResponse> signUp(@RequestBody SignUpRequest SignUpRequest) {
        return ResponseEntity.ok(authService.signUp(SignUpRequest));
    }

    @PostMapping("token")
    public ResponseEntity<SignInResponse> getToken(@RequestHeader(REFRESH_TOKEN) String refreshToken) {
        System.out.println(refreshToken);
        return ResponseEntity.ok(authService.refreshJwt(refreshToken));
    }

}
