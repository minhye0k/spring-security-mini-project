package mini.project.springsecurity.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@AllArgsConstructor
@Builder
public class SignInResponse {

    private String grantType;
    private String accessToken;
    private String refreshToken;

    public static SignInResponse of(String grantType,
                                    String accessToken,
                                    String refreshToken){
        return SignInResponse.builder()
                .grantType(grantType)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

}
