package mx.edu.chapingo.siani.domain;

import jakarta.persistence.*;
import lombok.*;


import java.time.LocalDateTime;


@Entity
@Table(name = "codigos_verificacion")
@Getter @Setter @Builder
@NoArgsConstructor @AllArgsConstructor
public class CodigoVerificacion {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "usuario_id", nullable = false)
    private Long usuarioId;

    @Column(nullable = false, length = 150)
    private String email;

    @Column(nullable = false, length = 6)
    private String codigo;

    @Column(nullable = false, length = 20)
    @Builder.Default
    private String tipo = "LOGIN_2FA";

    @Column(nullable = false)
    @Builder.Default
    private boolean usado = false;

    @Column(nullable = false)
    @Builder.Default
    private int intentos = 0;

    @Column(name = "max_intentos", nullable = false)
    @Builder.Default
    private int maxIntentos = 5;

    @Column(name = "expira_at", nullable = false)
    private LocalDateTime expiraAt;

    @Column(name = "usado_at")
    private LocalDateTime usadoAt;

    @Column(name = "ip_solicitante", length = 45)
    private String ipSolicitante;

    @Column(name = "created_at", nullable = false, updatable = false)
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    // ---- Helpers ----

    public boolean isExpirado() {
        return LocalDateTime.now().isAfter(expiraAt);
    }

    public boolean isMaxIntentosAlcanzado() {
        return intentos >= maxIntentos;
    }

    public boolean isValido() {
        return !usado && !isExpirado() && !isMaxIntentosAlcanzado();
    }
}
