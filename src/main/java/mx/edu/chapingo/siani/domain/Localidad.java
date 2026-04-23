package mx.edu.chapingo.siani.domain;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "cat_localidades", schema = "siani")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Localidad {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "municipio_id", nullable = false)
    private Municipio municipio;

    @Column(nullable = false, length = 200)
    private String nombre;

    @Column(nullable = false)
    private Boolean activo = true;
}
