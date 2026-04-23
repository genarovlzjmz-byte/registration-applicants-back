package mx.edu.chapingo.siani.dto.request;

import jakarta.validation.constraints.*;
import lombok.*;
import java.time.LocalDate;

/**
 * Request para el registro completo del alumno.
 * Incluye todos los datos del wizard multi-step.
 */
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class AlumnoRegistroRequest {

    // ---- Datos personales ----
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

    private LocalDate fechaNacimiento;

    @Pattern(regexp = "^[MFX]$", message = "Sexo inválido")
    private String sexo;

    @NotBlank(message = "El correo electrónico es obligatorio")
    @Email(message = "Formato de correo inválido")
    private String email;

    @NotBlank(message = "La confirmación de correo es obligatoria")
    @Email
    private String emailConfirmacion;

    @Size(max = 20)
    private String telefono;

    @NotBlank(message = "La contraseña es obligatoria")
    @Size(min = 8, message = "La contraseña debe tener al menos 8 caracteres")
    private String password;

    @NotBlank(message = "La confirmación de contraseña es obligatoria")
    private String passwordConfirmacion;

    // ---- Datos académicos ----
    @NotNull(message = "La modalidad de ingreso es obligatoria")
    private Long modalidadId;

    @NotBlank(message = "El tipo de ingreso es obligatorio")
    @Pattern(regexp = "^(REGULAR|REGIONAL)$", message = "Tipo de ingreso inválido")
    private String tipoIngreso;

    @Size(max = 255)
    private String escuelaProcedencia;

    // ---- Ubicación ----
    @NotNull(message = "El estado es obligatorio")
    private Long estadoId;

    @NotNull(message = "El municipio es obligatorio")
    private Long municipioId;

    private Long localidadId;

    // ---- Términos ----
    @AssertTrue(message = "Debe aceptar los términos y condiciones")
    private Boolean aceptaTerminos;
}
