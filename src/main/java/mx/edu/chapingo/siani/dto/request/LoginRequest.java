package mx.edu.chapingo.siani.dto.request;

import jakarta.validation.constraints.*;
import lombok.*;

// ============================================================================
// LOGIN
// ============================================================================
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class LoginRequest {

    @NotBlank(message = "El correo electrónico es obligatorio")
    @Email(message = "Formato de correo inválido")
    private String email;

    @NotBlank(message = "La CURP es obligatoria")
    @Size(min = 18, max = 18, message = "La CURP debe tener 18 caracteres")
    private String curp;

    @NotBlank(message = "La contraseña es obligatoria")
    private String password;
}
