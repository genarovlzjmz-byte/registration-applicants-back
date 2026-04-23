package mx.edu.chapingo.siani.domain;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
@Table(name = "alumnos", schema = "siani")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Alumno {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "usuario_id", nullable = false)
    private Usuario usuario;

    @Column(nullable = false, unique = true, length = 18)
    private String curp;

    @Column(nullable = false, length = 100)
    private String nombre;

    @Column(name = "apellido_paterno", nullable = false, length = 100)
    private String apellidoPaterno;

    @Column(name = "apellido_materno", length = 100)
    private String apellidoMaterno;

    @Column(name = "fecha_nacimiento")
    private LocalDate fechaNacimiento;

    @Column(length = 1)
    private String sexo;

    @Column(nullable = false, unique = true, length = 150)
    private String email;

    @Column(name = "email_confirmacion", length = 150)
    private String emailConfirmacion;

    @Column(length = 20)
    private String telefono;

    // Datos académicos
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "modalidad_id", nullable = false)
    private ModalidadIngreso modalidad;

    @Column(name = "tipo_ingreso", nullable = false, length = 20)
    private String tipoIngreso;

    @Column(name = "escuela_procedencia", length = 255)
    private String escuelaProcedencia;

    // Ubicación
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "estado_id", nullable = false)
    private Estado estado;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "municipio_id", nullable = false)
    private Municipio municipio;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "localidad_id")
    private Localidad localidad;

    // Control
    @Column(unique = true, length = 20)
    private String folio;

    @Column(nullable = false, length = 20)
    private String estatus;

    @Column(name = "acepta_terminos", nullable = false)
    private Boolean aceptaTerminos;

    @Column(name = "fecha_registro", nullable = false, updatable = false)
    private LocalDateTime fechaRegistro;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        if (tipoIngreso == null) tipoIngreso = "REGULAR";
        if (estatus == null) estatus = "REGISTRADO";
        if (aceptaTerminos == null) aceptaTerminos = false;
        fechaRegistro = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
