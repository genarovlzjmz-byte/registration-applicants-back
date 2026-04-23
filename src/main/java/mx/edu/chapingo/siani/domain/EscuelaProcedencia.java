package mx.edu.chapingo.siani.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "escuela_procedencia", schema = "siani")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class EscuelaProcedencia {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @JsonIgnore
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "alumno_id", nullable = false, unique = true)
    private Alumno alumno;

    @Column(name = "tipo_sistema_educativo", length = 20)
    private String tipoSistemaEducativo;

    @Column(name = "clave_cct", length = 30)
    private String claveCCT;

    @Column(name = "nombre_escuela", length = 255)
    private String nombreEscuela;

    @Column(name = "estado_escuela_id")
    private Long estadoEscuelaId;

    @Column(name = "municipio_escuela_id")
    private Long municipioEscuelaId;

    @Column(name = "localidad_escuela_id")
    private Long localidadEscuelaId;

    @Column(name = "codigo_postal_escuela", length = 10)
    private String codigoPostalEscuela;

    @Column(name = "colonia_escuela", length = 150)
    private String coloniaEscuela;

    @Column(name = "calle_escuela", length = 255)
    private String calleEscuela;

    @Column(name = "num_ext_escuela", length = 20)
    private String numExtEscuela;

    @Column(name = "tipo_escuela", length = 30)
    private String tipoEscuela;

    @Column(name = "clasificacion_educativa", length = 20)
    private String clasificacionEducativa;

    @Column(nullable = false)
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
