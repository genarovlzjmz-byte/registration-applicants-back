package mx.edu.chapingo.siani.dto.request;

import jakarta.validation.constraints.*;
import lombok.*;
import java.math.BigDecimal;
import java.time.LocalDate;

public class AspiranteRequests {

    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class DatosPersonalesRequest {
        private LocalDate fechaNacimiento;
        private Long entidadNacimientoId;
        private Long municipioNacimientoId;
        @Pattern(regexp = "^[MF]$", message = "Sexo debe ser M o F")
        private String sexo;
        @Size(max = 15) private String telefonoFijo;
        @Size(max = 15) private String telefonoCelular;
        @Pattern(regexp = "^(SI|NO)$", message = "Valor debe ser SI o NO")
        private String fueAlumnoChapingo;
        @Size(max = 20) private String matriculaChapingo;
        private String nivelChapingo;
        private Integer gradoChapingo;
    }

    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class DatosPadresRequest {
        @Pattern(regexp = "^(SI|NO|FINADO)$") private String padreLabora;
        @Size(max = 100) private String padreNombre;
        @Size(max = 100) private String padreApellidoPaterno;
        @Size(max = 100) private String padreApellidoMaterno;
        @Size(max = 100) private String padreOcupacion;
        @DecimalMin("0") private BigDecimal padreIngresoMensual;

        @Pattern(regexp = "^(SI|NO|FINADO)$") private String madreLabora;
        @Size(max = 100) private String madreNombre;
        @Size(max = 100) private String madreApellidoPaterno;
        @Size(max = 100) private String madreApellidoMaterno;
        @Size(max = 100) private String madreOcupacion;
        @DecimalMin("0") private BigDecimal madreIngresoMensual;
    }

    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class DomicilioRequest {
        @NotBlank @Size(max = 5) private String codigoPostal;
        @Size(max = 200) private String colonia;
        @Size(max = 200) private String calle;
        @Size(max = 20) private String numExterior;
        @Size(max = 20) private String numInterior;
        @Size(max = 20) private String manzana;
        @Size(max = 20) private String lote;
        @Size(max = 200) private String entreCalle1;
        @Size(max = 200) private String entreCalle2;
        @Size(max = 500) private String referencia;
    }

    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class ContactoEmergenciaRequest {
        @NotBlank @Size(max = 100) private String nombre;
        @NotBlank @Size(max = 100) private String apellidoPaterno;
        @Size(max = 100) private String apellidoMaterno;
        @NotBlank @Size(max = 15) private String telefonoCelular;
    }

    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class EscuelaProcedenciaRequest {
        @Pattern(regexp = "^(PUBLICO|PRIVADO)$") private String tipoSistemaEducativo;
        @Size(max = 20) private String claveCCT;
        @Size(max = 200) private String nombreEscuela;
        private Long estadoEscuelaId;
        private Long municipioEscuelaId;
        private Long localidadEscuelaId;
        @Size(max = 5) private String codigoPostalEscuela;
        @Size(max = 200) private String coloniaEscuela;
        @Size(max = 200) private String calleEscuela;
        @Size(max = 20) private String numExtEscuela;
        private String tipoEscuela;
        @Pattern(regexp = "^(RURAL|URBANA|SEMIURBANA)$") private String clasificacionEducativa;
    }

    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class ConfirmacionRequest {
        private Long estadoSedeId;
        private Long sedeId;
        @Size(max = 200) private String escuelaSede;
    }
}
