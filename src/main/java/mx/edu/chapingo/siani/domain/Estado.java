package mx.edu.chapingo.siani.domain;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDate;
import java.time.LocalDateTime;

// ============================================================================
// ESTADO
// ============================================================================
@Entity
@Table(name = "cat_estados", schema = "siani")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Estado {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 100)
    private String nombre;

    @Column(length = 10)
    private String abreviatura;

    @Column(nullable = false)
    private Boolean activo = true;
}
