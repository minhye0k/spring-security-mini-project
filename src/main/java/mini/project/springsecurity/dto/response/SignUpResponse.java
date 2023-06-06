package mini.project.springsecurity.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class SignUpResponse {

    private String grantType;
    private String accessToken;
    private String refreshToken;

    public static SignUpResponse of(String grantType,
                                    String accessToken,
                                    String refreshToken){
        return SignUpResponse.builder()
                .grantType(grantType)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }
}
