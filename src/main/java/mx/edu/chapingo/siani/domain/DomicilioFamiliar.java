package mx.edu.chapingo.siani.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "domicilio_familiar", schema = "siani")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class DomicilioFamiliar {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @JsonIgnore
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "alumno_id", nullable = false, unique = true)
    private Alumno alumno;

    // Estado, municipio, localidad ya están en Alumno - aquí van los campos extra
    @Column(name = "codigo_postal", length = 10)
    private String codigoPostal;
    @Column(length = 150)
    private String colonia;
    @Column(length = 255)
    private String calle;
    @Column(name = "num_exterior", length = 20)
    private String numExterior;
    @Column(name = "num_interior", length = 20)
    private String numInterior;
    @Column(length = 20)
    private String manzana;
    @Column(length = 20)
    private String lote;
    @Column(name = "entre_calle1", length = 255)
    private String entreCalle1;
    @Column(name = "entre_calle2", length = 255)
    private String entreCalle2;
    @Column(length = 500)
    private String referencia;

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
