package mx.edu.chapingo.siani.dto.response;

import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ColoniaResponse {
    private Long id;
    private Long codigoPostalId;
    private String nombre;
    private String tipoAsentamiento;
    private String zona;
}

