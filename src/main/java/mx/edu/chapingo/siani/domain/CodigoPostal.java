package mx.edu.chapingo.siani.domain;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "cat_codigos_postales", schema = "siani")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class CodigoPostal {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 10)
    private String codigo;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "municipio_id", nullable = false)
    private Municipio municipio;

    @Column(nullable = false)
    private Boolean activo;

    @PrePersist
    protected void onCreate() {
        if (activo == null) activo = true;
    }
}

