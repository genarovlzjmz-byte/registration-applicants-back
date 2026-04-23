package mx.edu.chapingo.siani.dto.response;
import lombok.*;
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class ValidacionRegionalResponse {
    private Boolean elegible;
    private Long estadoId;
    private Long municipioId;
    private String estadoNombre;
    private String municipioNombre;
    private String mensaje;
}
