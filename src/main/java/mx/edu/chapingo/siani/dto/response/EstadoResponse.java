package mx.edu.chapingo.siani.dto.response;
import lombok.*;
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class EstadoResponse {
    private Long id;
    private String nombre;
    private String abreviatura;
}
