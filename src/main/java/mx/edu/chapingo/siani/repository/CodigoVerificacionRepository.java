package mx.edu.chapingo.siani.repository;

import mx.edu.chapingo.siani.domain.CodigoVerificacion;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface CodigoVerificacionRepository extends JpaRepository<CodigoVerificacion, Long> {

    /**
     * Busca el código más reciente no usado y no expirado para un usuario.
     */
    @Query("""
        SELECT c FROM CodigoVerificacion c 
        WHERE c.usuarioId = :usuarioId 
          AND c.tipo = :tipo
          AND c.usado = false 
          AND c.expiraAt > :ahora
          AND c.intentos < c.maxIntentos
        ORDER BY c.createdAt DESC 
        LIMIT 1
        """)
    Optional<CodigoVerificacion> findCodigoActivo(Long usuarioId, String tipo, LocalDateTime ahora);

    /**
     * Invalida todos los códigos pendientes de un usuario (cuando se genera uno nuevo).
     */
    @Modifying
    @Query("""
        UPDATE CodigoVerificacion c 
        SET c.usado = true, c.usadoAt = :ahora 
        WHERE c.usuarioId = :usuarioId 
          AND c.tipo = :tipo
          AND c.usado = false
        """)
    void invalidarCodigosPendientes(Long usuarioId, String tipo, LocalDateTime ahora);

    /**
     * Limpia códigos expirados (para un job programado).
     */
    @Modifying
    @Query("DELETE FROM CodigoVerificacion c WHERE c.expiraAt < :limite")
    int limpiarExpirados(LocalDateTime limite);
}
