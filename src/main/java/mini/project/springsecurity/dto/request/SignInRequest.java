package mini.project.springsecurity.dto.request;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class SignInRequest {
    private String email;
    private String password;

}
