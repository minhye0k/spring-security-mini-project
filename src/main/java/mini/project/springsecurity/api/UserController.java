package mini.project.springsecurity.api;


import lombok.RequiredArgsConstructor;
import mini.project.springsecurity.entity.Authority;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("users")
public class UserController {
    @GetMapping
    ResponseEntity user(Authentication authentication) {
        System.out.println(authentication.getPrincipal().toString());
        authentication.getAuthorities().forEach((a) -> System.out.println(a.getAuthority().toString()));
        System.out.println(Authority.ROLE_ADMIN.name());

        return ResponseEntity.ok().build();
    }
}
