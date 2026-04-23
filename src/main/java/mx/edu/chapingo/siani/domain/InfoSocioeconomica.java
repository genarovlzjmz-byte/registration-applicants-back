package mx.edu.chapingo.siani.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Table(name = "info_socioeconomica", schema = "siani")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class InfoSocioeconomica {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @JsonIgnore
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "alumno_id", nullable = false, unique = true)
    private Alumno alumno;

    // --- 1. Información escolar ---
    @Column(name = "promedio_general", precision = 4, scale = 2)
    private BigDecimal promedioGeneral;
    @Column(name = "beca_escolar", length = 2)
    private String becaEscolar;
    @Column(name = "tipo_beca", length = 100)
    private String tipoBeca;

    // --- 2. Responsable económico ---
    @Column(name = "resp_parentesco", length = 50)
    private String respParentesco;
    @Column(name = "resp_nombre", length = 200)
    private String respNombre;
    @Column(name = "resp_ocupacion", length = 150)
    private String respOcupacion;
    @Column(name = "resp_ingreso_mensual", precision = 12, scale = 2)
    private BigDecimal respIngresoMensual;
    @Column(name = "resp_escolaridad", length = 50)
    private String respEscolaridad;

    // --- 3. Pareja del responsable ---
    @Column(name = "pareja_ocupacion", length = 150)
    private String parejaOcupacion;
    @Column(name = "pareja_ingreso_mensual", precision = 12, scale = 2)
    private BigDecimal parejaIngresoMensual;
    @Column(name = "pareja_escolaridad", length = 50)
    private String parejaEscolaridad;

    // --- 4. Otros ingresos ---
    @Column(name = "otros_ingresos_monto", precision = 12, scale = 2)
    private BigDecimal otrosIngresosMonto;
    @Column(name = "otros_ingresos_fuente", length = 200)
    private String otrosIngresosFuente;

    // --- 5. Vivienda ---
    @Column(name = "vivienda_tipo", length = 30)
    private String viviendaTipo;
    @Column(name = "vivienda_propiedad", length = 30)
    private String viviendaPropiedad;
    @Column(name = "vivienda_material_paredes", length = 50)
    private String viviendaMaterialParedes;
    @Column(name = "vivienda_material_techo", length = 50)
    private String viviendaMaterialTecho;
    @Column(name = "vivienda_material_piso", length = 50)
    private String viviendaMaterialPiso;
    @Column(name = "vivienda_num_cuartos")
    private Short viviendaNumCuartos;
    @Column(name = "vivienda_num_personas")
    private Short viviendaNumPersonas;

    // --- 6. Bienes y servicios ---
    @Column(name = "tiene_agua_potable")
    private Boolean tieneAguaPotable;
    @Column(name = "tiene_energia_electrica")
    private Boolean tieneEnergiaElectrica;
    @Column(name = "tiene_drenaje")
    private Boolean tieneDrenaje;
    @Column(name = "tiene_internet")
    private Boolean tieneInternet;
    @Column(name = "tiene_vehiculo")
    private Boolean tieneVehiculo;
    @Column(name = "tiene_computadora")
    private Boolean tieneComputadora;
    @Column(name = "tiene_telefono")
    private Boolean tieneTelefono;

    // --- Sub-secciones completadas (6 bits) ---
    @Column(name = "seccion1_completa")
    private Boolean seccion1Completa;
    @Column(name = "seccion2_completa")
    private Boolean seccion2Completa;
    @Column(name = "seccion3_completa")
    private Boolean seccion3Completa;
    @Column(name = "seccion4_completa")
    private Boolean seccion4Completa;
    @Column(name = "seccion5_completa")
    private Boolean seccion5Completa;
    @Column(name = "seccion6_completa")
    private Boolean seccion6Completa;

    @Column(nullable = false)
    private Boolean completado;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        if (seccion1Completa == null) seccion1Completa = false;
        if (seccion2Completa == null) seccion2Completa = false;
        if (seccion3Completa == null) seccion3Completa = false;
        if (seccion4Completa == null) seccion4Completa = false;
        if (seccion5Completa == null) seccion5Completa = false;
        if (seccion6Completa == null) seccion6Completa = false;
        if (completado == null) completado = false;
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
