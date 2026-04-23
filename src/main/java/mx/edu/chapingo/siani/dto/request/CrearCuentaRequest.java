package mx.edu.chapingo.siani.dto.request;

import jakarta.validation.constraints.*;
import lombok.*;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class CrearCuentaRequest {

    @NotBlank(message = "La CURP es obligatoria")
    @Size(min = 18, max = 18, message = "La CURP debe tener 18 caracteres")
    @Pattern(regexp = "^[A-Z]{4}\\d{6}[HM][A-Z]{5}[A-Z0-9]\\d$",
             message = "Formato de CURP inválido")
    private String curp;

    @NotBlank(message = "El nombre es obligatorio")
    @Size(max = 100)
    private String nombre;

    @NotBlank(message = "El primer apellido es obligatorio")
    @Size(max = 100)
    private String apellidoPaterno;

    @Size(max = 100)
    private String apellidoMaterno;

    @NotBlank(message = "El correo electrónico es obligatorio")
    @Email(message = "Formato de correo inválido")
    private String email;

    @NotBlank(message = "La confirmación de correo es obligatoria")
    @Email
    private String emailConfirmacion;

    @NotBlank(message = "La contraseña es obligatoria")
    @Size(min = 8, message = "La contraseña debe tener al menos 8 caracteres")
    private String password;

    @NotBlank(message = "La confirmación de contraseña es obligatoria")
    private String passwordConfirmacion;

    // Datos de ubicación (paso previo del wizard)
    @NotNull(message = "El estado es obligatorio")
    private Long estadoId;

    @NotNull(message = "El municipio es obligatorio")
    private Long municipioId;

    private Long localidadId;

    // Modalidad seleccionada
    @NotNull(message = "La modalidad de ingreso es obligatoria")
    private Long modalidadId;

    // Datos opcionales del paso de encuesta
    private Boolean conoceOfertaEducativa;
    private String programaInteres;
}
