package mx.edu.chapingo.siani.domain;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "cat_municipios", schema = "siani")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Municipio {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "estado_id", nullable = false)
    private Estado estado;

    @Column(nullable = false, length = 150)
    private String nombre;

    @Column(nullable = false)
    private Boolean activo = true;
}
