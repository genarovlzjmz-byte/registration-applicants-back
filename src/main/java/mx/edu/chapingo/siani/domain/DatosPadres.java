package mx.edu.chapingo.siani.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Table(name = "datos_padres", schema = "siani")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class DatosPadres {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @JsonIgnore
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "alumno_id", nullable = false, unique = true)
    private Alumno alumno;

    // --- Padre ---
    @Column(name = "padre_labora", length = 10)
    private String padreLabora;
    @Column(name = "padre_nombre", length = 100)
    private String padreNombre;
    @Column(name = "padre_apellido_paterno", length = 100)
    private String padreApellidoPaterno;
    @Column(name = "padre_apellido_materno", length = 100)
    private String padreApellidoMaterno;
    @Column(name = "padre_ocupacion", length = 150)
    private String padreOcupacion;
    @Column(name = "padre_ingreso_mensual", precision = 12, scale = 2)
    private BigDecimal padreIngresoMensual;

    // --- Madre ---
    @Column(name = "madre_labora", length = 10)
    private String madreLabora;
    @Column(name = "madre_nombre", length = 100)
    private String madreNombre;
    @Column(name = "madre_apellido_paterno", length = 100)
    private String madreApellidoPaterno;
    @Column(name = "madre_apellido_materno", length = 100)
    private String madreApellidoMaterno;
    @Column(name = "madre_ocupacion", length = 150)
    private String madreOcupacion;
    @Column(name = "madre_ingreso_mensual", precision = 12, scale = 2)
    private BigDecimal madreIngresoMensual;

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
