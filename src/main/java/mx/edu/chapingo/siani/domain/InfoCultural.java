package mx.edu.chapingo.siani.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "info_cultural", schema = "siani")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class InfoCultural {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @JsonIgnore
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "alumno_id", nullable = false, unique = true)
    private Alumno alumno;

    // --- Origen indígena ---
    @Column(name = "pertenece_pueblo_indigena", length = 2)
    private String pertencePuebloIndigena;

    @Column(name = "pueblo_indigena", length = 100)
    private String puebloIndigena;

    @Column(name = "lengua_materna_habla")
    private Boolean lenguaMaternaHabla;
    @Column(name = "lengua_materna_escribe")
    private Boolean lenguaMaternaEscribe;
    @Column(name = "lengua_materna_comprende")
    private Boolean lenguaMaternaComprende;
    @Column(name = "lengua_materna_ninguna")
    private Boolean lenguaMaternaNinguna;

    @Column(name = "familiar_indigena", length = 2)
    private String familiarIndigena;
    @Column(name = "familiar_indigena_padre")
    private Boolean familiarIndigenaPadre;
    @Column(name = "familiar_indigena_madre")
    private Boolean familiarIndigenaMadre;
    @Column(name = "familiar_indigena_abuelos")
    private Boolean familiarIndigenaAbuelos;

    // --- Pertenencia afromexicana ---
    @Column(name = "afromexicano", length = 2)
    private String afromexicano;
    @Column(name = "identificacion_afromexicana", length = 20)
    private String identificacionAfromexicana;
    @Column(name = "vinculos_afromexicanos", length = 2)
    private String vinculosAfromexicanos;
    @Column(name = "region_afromexicana", length = 2)
    private String regionAfromexicana;

    // --- Condición funcional ---
    @Column(name = "tiene_discapacidad", length = 2)
    private String tieneDiscapacidad;
    @Column(name = "discapacidad_fisica_motriz")
    private Boolean discapacidadFisicaMotriz;
    @Column(name = "discapacidad_intelectual")
    private Boolean discapacidadIntelectual;
    @Column(name = "discapacidad_auditiva_hipoacusia")
    private Boolean discapacidadAuditivaHipoacusia;
    @Column(name = "discapacidad_auditiva_sordera")
    private Boolean discapacidadAuditivaSordera;
    @Column(name = "discapacidad_visual_baja")
    private Boolean discapacidadVisualBaja;
    @Column(name = "discapacidad_visual_ceguera")
    private Boolean discapacidadVisualCeguera;
    @Column(name = "discapacidad_ninguna")
    private Boolean discapacidadNinguna;

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
