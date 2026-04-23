package mx.edu.chapingo.siani.dto.response;
import lombok.*;
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class ModalidadResponse {
    private Long id;
    private String clave;
    private String nombre;
    private String descripcion;
    private Boolean requiereValidacionRegional;
    private Integer orden;
}
