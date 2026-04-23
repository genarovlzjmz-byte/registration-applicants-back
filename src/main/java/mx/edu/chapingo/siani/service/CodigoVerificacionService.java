package mx.edu.chapingo.siani.service;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import mx.edu.chapingo.siani.domain.CodigoVerificacion;
import mx.edu.chapingo.siani.exception.BusinessException;
import mx.edu.chapingo.siani.repository.CodigoVerificacionRepository;
import mx.edu.chapingo.siani.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class CodigoVerificacionService {

    private final CodigoVerificacionRepository codigoRepository;
    private final UsuarioRepository usuarioRepository;
    private final EmailService emailService;

    private final SecureRandom random = new SecureRandom();

    @Value("${quimios.otp.expiration-minutes:5}")
    private int expirationMinutes;

    @Value("${quimios.otp.max-intentos:5}")
    private int maxIntentos;

    // ============================================================
    // GENERAR Y ENVIAR CÓDIGO
    // ============================================================

    /**
     * Genera un código de 6 dígitos, lo guarda en BD, y lo envía por email.
     * 
     * Se llama después de que el login con password fue exitoso.
     * Invalida cualquier código pendiente anterior del mismo usuario.
     * 
     * @param usuarioId ID del usuario en la tabla usuarios
     * @param email Email del usuario
     * @param ip IP del cliente que solicita el código
     * @return El código generado (solo para testing — en producción no se retorna)
     */
    @Transactional
    public String generarYEnviar(Long usuarioId, String email, String ip) {
        // 1. Invalidar códigos pendientes anteriores
        codigoRepository.invalidarCodigosPendientes(usuarioId, "LOGIN_2FA", LocalDateTime.now());

        // 2. Generar código aleatorio de 6 dígitos
        String codigo = String.format("%06d", random.nextInt(1_000_000));

        // 3. Guardar en BD
        CodigoVerificacion entity = CodigoVerificacion.builder()
                .usuarioId(usuarioId)
                .email(email)
                .codigo(codigo)
                .tipo("LOGIN_2FA")
                .expiraAt(LocalDateTime.now().plusMinutes(expirationMinutes))
                .maxIntentos(maxIntentos)
                .ipSolicitante(ip)
                .build();
        codigoRepository.save(entity);

        // 4. Enviar por email
        emailService.enviarCodigoVerificacion(email, codigo, expirationMinutes);

        log.info("Código 2FA generado para usuario {} (email: {}), expira en {} min",
                usuarioId, email, expirationMinutes);

        return codigo; // En producción podrías no retornarlo
    }

    // ============================================================
    // VERIFICAR CÓDIGO
    // ============================================================

    /**
     * Verifica el código de 6 dígitos ingresado por el usuario.
     * 
     * @param usuarioId ID del usuario
     * @param codigoIngresado Código que el usuario escribió
     * @return true si el código es válido
     * @throws BusinessException si no hay código activo o se excedieron los intentos
     */
    @Transactional
    public boolean verificarCodigo(Long usuarioId, String codigoIngresado) {
        CodigoVerificacion codigo = codigoRepository
                .findCodigoActivo(usuarioId, "LOGIN_2FA", LocalDateTime.now())
                .orElseThrow(() -> new BusinessException(
                        "No hay código de verificación activo. Solicita uno nuevo."));

        // Verificar si expiró
        if (codigo.isExpirado()) {
            throw new BusinessException("El código ha expirado. Solicita uno nuevo.");
        }

        // Verificar intentos
        if (codigo.isMaxIntentosAlcanzado()) {
            throw new BusinessException("Demasiados intentos fallidos. Solicita un código nuevo.");
        }

        // Comparar código
        if (codigo.getCodigo().equals(codigoIngresado)) {
            // Código válido — marcarlo como usado
            codigo.setUsado(true);
            codigo.setUsadoAt(LocalDateTime.now());
            codigoRepository.save(codigo);
            log.info("Código 2FA verificado exitosamente para usuario {}", usuarioId);
            return true;
        } else {
            // Código incorrecto — incrementar intentos
            codigo.setIntentos(codigo.getIntentos() + 1);
            codigoRepository.save(codigo);
            log.warn("Código 2FA incorrecto para usuario {} (intento {}/{})",
                    usuarioId, codigo.getIntentos(), codigo.getMaxIntentos());
            return false;
        }
    }

    // ============================================================
    // LIMPIEZA
    // ============================================================

    /**
     * Limpia códigos expirados de más de 1 hora.
     * Llamar desde un @Scheduled o un cron job.
     */
    @Transactional
    public int limpiarExpirados() {
        int eliminados = codigoRepository.limpiarExpirados(
                LocalDateTime.now().minusHours(1));
        if (eliminados > 0) {
            log.info("Limpiados {} códigos de verificación expirados", eliminados);
        }
        return eliminados;
    }
}
