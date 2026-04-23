package mx.edu.chapingo.siani.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDate;
import java.time.LocalDateTime;

/**
 * Datos personales extendidos del aspirante (post-login).
 * Complementa los datos básicos capturados en el registro inicial.
 */
@Entity
@Table(name = "datos_personales_aspirante", schema = "siani")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class DatosPersonalesAspirante {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @JsonIgnore
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "alumno_id", nullable = false, unique = true)
    private Alumno alumno;

    @Column(name = "fecha_nacimiento")
    private LocalDate fechaNacimiento;

    @Column(name = "entidad_nacimiento_id")
    private Long entidadNacimientoId;

    @Column(name = "municipio_nacimiento_id")
    private Long municipioNacimientoId;

    @Column(columnDefinition = "bpchar(1)")
    private String sexo;

    @Column(name = "telefono_fijo", length = 20)
    private String telefonoFijo;

    @Column(name = "telefono_celular", length = 20)
    private String telefonoCelular;

    @Column(name = "fue_alumno_chapingo", length = 2)
    private String fueAlumnoChapingo;

    @Column(name = "matricula_chapingo", length = 20)
    private String matriculaChapingo;

    @Column(name = "nivel_chapingo", length = 20)
    private String nivelChapingo;

    @Column(name = "grado_chapingo")
    private Short gradoChapingo;

    @Column(name = "completado", nullable = false)
    private Boolean completado;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        if (completado == null) {
            completado = false;
        }
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
