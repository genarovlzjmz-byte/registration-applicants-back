package mx.edu.chapingo.siani.dto.response;

import lombok.*;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AlumnoCompletoDatosResponse {

    // Datos del Alumno
    private Long id;
    private String folio;
    private String curp;
    private String nombre;
    private String apellidoPaterno;
    private String apellidoMaterno;
    private LocalDate fechaNacimiento;
    private String sexo;
    private String email;
    private String telefono;
    private String modalidadNombre;
    private String modalidadClave;
    private String tipoIngreso;
    private String escuelaProcedencia;
    private String estadoNombre;
    private Long estadoIdAlumno;
    private String municipioNombre;
    private Long municipioIdAlumno;
    private String localidadNombre;
    private String estatus;
    private LocalDateTime fechaRegistro;

    // Datos Personales Aspirante
    private Long datosPersonalesId;
    private Long entidadNacimientoId;
    private Long municipioNacimientoId;
    private String telefonoFijo;
    private String telefonoCelular;
    private String fueAlumnoChapingo;
    private String matriculaChapingo;
    private String nivelChapingo;
    private Short gradoChapingo;
    private Boolean datosPersonalesCompletado;
}
