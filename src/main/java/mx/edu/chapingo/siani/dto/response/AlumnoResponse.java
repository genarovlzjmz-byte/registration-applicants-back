package mx.edu.chapingo.siani.dto.response;
import lombok.*;
import java.time.LocalDate;
import java.time.LocalDateTime;
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class AlumnoResponse {
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
    private String municipioNombre;
    private String localidadNombre;
    private String estatus;
    private LocalDateTime fechaRegistro;
}
