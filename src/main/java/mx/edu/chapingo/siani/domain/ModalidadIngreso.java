package mx.edu.chapingo.siani.domain;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "cat_modalidades_ingreso", schema = "siani")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class ModalidadIngreso {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 100)
    private String clave;

    @Column(nullable = false, length = 255)
    private String nombre;

    @Column(columnDefinition = "TEXT")
    private String descripcion;

    @Column(name = "requiere_validacion_regional", nullable = false)
    private Boolean requiereValidacionRegional = false;

    @Column(nullable = false)
    private Boolean activo = true;

    @Column(nullable = false)
    private Integer orden = 0;
}
