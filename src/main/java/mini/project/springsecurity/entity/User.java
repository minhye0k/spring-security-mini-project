package mini.project.springsecurity.entity;

import lombok.*;

import javax.persistence.*;

@Entity
@Table
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long seq;

    private String email;
    private String password;

    @Enumerated(EnumType.STRING)
    private Authority authority;

    public static User of(String email,
                          String password) {
        return User.builder()
                .email(email)
                .password(password)
                .authority(Authority.ROLE_USER)
                .build();
    }
}
