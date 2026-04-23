package mx.edu.chapingo.siani.dto.response;
import lombok.*;
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class TokenResponse {
    private String token;
    private String tipo;
    private Long expiresIn;
    private String email;
    private String curp;
    private String nombre;
    private String rol;
}
