package mx.edu.chapingo.siani.dto.response;

import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CodigoPostalResponse {
    private Long id;
    private String codigo;
    private Long municipioId;
}

