package mx.edu.chapingo.siani.dto.response;

import lombok.*;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CodigoPostalConColoniasResponse {
    private Long id;
    private String codigo;
    private Long municipioId;
    private String municipioNombre;
    private Long estadoId;
    private String estadoNombre;
    private List<ColoniaResponse> colonias;
}

