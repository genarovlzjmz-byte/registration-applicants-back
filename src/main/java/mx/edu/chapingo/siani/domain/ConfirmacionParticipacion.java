package mx.edu.chapingo.siani.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "confirmacion_participacion", schema = "siani")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class ConfirmacionParticipacion {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @JsonIgnore
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "alumno_id", nullable = false, unique = true)
    private Alumno alumno;

    @Column(nullable = false)
    private Boolean confirmado;

    @Column(nullable = false)
    private Boolean cancelado;

    @Column(name = "estado_sede_id")
    private Long estadoSedeId;

    @Column(name = "sede_id")
    private Long sedeId;

    @Column(name = "escuela_sede", length = 255)
    private String escuelaSede;

    @Column(name = "fecha_confirmacion")
    private LocalDateTime fechaConfirmacion;

    @Column(name = "fecha_cancelacion")
    private LocalDateTime fechaCancelacion;

    @Column(nullable = false)
    private Boolean completado;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        if (confirmado == null) confirmado = false;
        if (cancelado == null) cancelado = false;
        if (completado == null) completado = false;
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
