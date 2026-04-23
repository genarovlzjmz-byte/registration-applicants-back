package mx.edu.chapingo.siani.dto.response;
import lombok.*;
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class MunicipioResponse {
    private Long id;
    private Long estadoId;
    private String nombre;
}
