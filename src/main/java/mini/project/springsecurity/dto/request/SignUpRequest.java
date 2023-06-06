package mini.project.springsecurity.dto.request;

import lombok.Data;

@Data
public class SignUpRequest {
    private final String email;
    private final String password;

}
