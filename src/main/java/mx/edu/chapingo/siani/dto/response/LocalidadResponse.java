package mx.edu.chapingo.siani.dto.response;
import lombok.*;
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class LocalidadResponse {
    private Long id;
    private Long municipioId;
    private String nombre;
}
