package mx.edu.chapingo.siani.domain;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "cat_colonias", schema = "siani")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Colonia {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 200)
    private String nombre;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "codigo_postal_id", nullable = false)
    private CodigoPostal codigoPostal;

    @Column(name = "tipo_asentamiento", length = 100)
    private String tipoAsentamiento;

    @Column(length = 50)
    private String zona;

    @Column(nullable = false)
    private Boolean activo;

    @PrePersist
    protected void onCreate() {
        if (activo == null) activo = true;
    }
}

