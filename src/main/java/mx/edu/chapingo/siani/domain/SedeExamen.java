package mx.edu.chapingo.siani.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "cat_sedes_examen", schema = "siani")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class SedeExamen {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 200, nullable = false)
    private String nombre;

    @Column(name = "escuela", length = 255)
    private String escuela;

    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "estado_id", nullable = false)
    private Estado estado;

    @Column(name = "direccion", length = 500)
    private String direccion;

    @Column(nullable = false)
    private Boolean activo;

    @PrePersist
    protected void onCreate() {
        if (activo == null) activo = true;
    }
}
