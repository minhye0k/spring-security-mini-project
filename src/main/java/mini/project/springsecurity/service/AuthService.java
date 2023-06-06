package mini.project.springsecurity.service;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import mini.project.springsecurity.dao.UserRepository;
import mini.project.springsecurity.dto.request.SignInRequest;
import mini.project.springsecurity.dto.request.SignUpRequest;
import mini.project.springsecurity.dto.response.SignInResponse;
import mini.project.springsecurity.dto.response.SignUpResponse;
import mini.project.springsecurity.entity.Authority;
import mini.project.springsecurity.entity.User;
import mini.project.springsecurity.exception.JwtInvalidException;
import mini.project.springsecurity.issuer.JwtIssuer;
import mini.project.springsecurity.utils.extractor.AuthorizationExtractor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final String BEARER = "Bearer";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtIssuer jwtIssuer;

    @Transactional
    public SignUpResponse signUp(SignUpRequest signUpRequest) {
        String email = signUpRequest.getEmail();
        Optional<User> userOptional = userRepository.findByEmail(email);

        if (userOptional.isPresent()) {
            throw new RuntimeException("email already exists");
        }

        String password = signUpRequest.getPassword();

        User user = User.of(email, passwordEncoder.encode(password));
        userRepository.save(user);

        return SignUpResponse.of(BEARER,
                jwtIssuer.issueAccessToken(user.getSeq(), Authority.ROLE_USER.toString()),
                jwtIssuer.issueRefreshToken(user.getSeq(), Authority.ROLE_USER.toString()));
    }

    @Transactional
    public SignInResponse signIn(SignInRequest signInRequest) {
        String email = signInRequest.getEmail();
        Optional<User> userOptional = userRepository.findByEmail(email);

        if (userOptional.isEmpty()) {
            throw new RuntimeException("email do not exists");
        }
        User user = userOptional.get();

        if (!passwordEncoder.matches(signInRequest.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("password do not matches");
        }

        return SignInResponse.of(BEARER,
                jwtIssuer.issueAccessToken(user.getSeq(), user.getAuthority().toString()),
                jwtIssuer.issueRefreshToken(user.getSeq(), user.getAuthority().toString()));
    }

    public SignInResponse refreshJwt(String refreshJwt) {
        if (!StringUtils.hasText(refreshJwt)) {
            throw new JwtInvalidException("invalid");
        }

        Claims claims = jwtIssuer.parseClaimsFromRefreshToken(refreshJwt);
        User user = userRepository.findById(Long.valueOf(claims.getSubject()))
                .orElseThrow(() -> new UsernameNotFoundException("username is not found"));

        return SignInResponse.of(BEARER,
                jwtIssuer.issueAccessToken(user.getSeq(), user.getAuthority().toString()),
                jwtIssuer.issueRefreshToken(user.getSeq(), user.getAuthority().toString()));
    }


}
