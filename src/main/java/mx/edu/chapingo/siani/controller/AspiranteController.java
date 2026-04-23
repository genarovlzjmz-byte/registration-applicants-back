package mx.edu.chapingo.siani.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import mx.edu.chapingo.siani.domain.*;
import mx.edu.chapingo.siani.dto.response.ApiResponse;
import mx.edu.chapingo.siani.service.AspiranteService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Controller para todas las secciones post-login del aspirante.
 * 
 * El usuario autenticado se obtiene del JWT via @AuthenticationPrincipal.
 * Cada endpoint opera sobre los datos del alumno asociado al usuario.
 */
@RestController
@RequestMapping("/aspirante")
@RequiredArgsConstructor
@Tag(name = "Aspirante", description = "API para gestión de datos del aspirante (requiere autenticación)")
@SecurityRequirement(name = "bearerAuth")
public class AspiranteController {

    private final AspiranteService aspiranteService;

    // ==================== ESTADO GENERAL ====================

    @Operation(summary = "Obtener estado de secciones", description = "Devuelve el estado de completitud de cada sección del formulario")
    @GetMapping("/estado-secciones")
    public ResponseEntity<ApiResponse<Map<String, String>>> getEstadoSecciones(
            @AuthenticationPrincipal Usuario usuario) {
        return ResponseEntity.ok(ApiResponse.ok(aspiranteService.getEstadoSecciones(usuario.getId())));
    }

    // ==================== DATOS PERSONALES ====================

    @Operation(summary = "Obtener datos personales", description = "Obtiene los datos personales del aspirante autenticado")
    @GetMapping("/datos-personales")
    public ResponseEntity<ApiResponse<DatosPersonalesAspirante>> getDatosPersonales(
            @AuthenticationPrincipal Usuario usuario) {
        return ResponseEntity.ok(ApiResponse.ok(aspiranteService.getDatosPersonales(usuario.getId())));
    }

    @Operation(summary = "Guardar datos personales", description = "Guarda o actualiza los datos personales del aspirante")
    @PutMapping("/datos-personales")
    public ResponseEntity<ApiResponse<DatosPersonalesAspirante>> guardarDatosPersonales(
            @AuthenticationPrincipal Usuario usuario,
            @RequestBody DatosPersonalesAspirante datos) {
        return ResponseEntity.ok(ApiResponse.ok("Datos personales guardados", 
                aspiranteService.guardarDatosPersonales(usuario.getId(), datos)));
    }

    // ==================== DATOS PADRES ====================

    @Operation(summary = "Obtener datos de padres")
    @GetMapping("/datos-padres")
    public ResponseEntity<ApiResponse<DatosPadres>> getDatosPadres(
            @AuthenticationPrincipal Usuario usuario) {
        return ResponseEntity.ok(ApiResponse.ok(aspiranteService.getDatosPadres(usuario.getId())));
    }

    @Operation(summary = "Guardar datos de padres")
    @PutMapping("/datos-padres")
    public ResponseEntity<ApiResponse<DatosPadres>> guardarDatosPadres(
            @AuthenticationPrincipal Usuario usuario,
            @RequestBody DatosPadres datos) {
        return ResponseEntity.ok(ApiResponse.ok("Datos de padres guardados",
                aspiranteService.guardarDatosPadres(usuario.getId(), datos)));
    }

    // ==================== DOMICILIO ====================

    @Operation(summary = "Obtener domicilio familiar")
    @GetMapping("/domicilio")
    public ResponseEntity<ApiResponse<DomicilioFamiliar>> getDomicilio(
            @AuthenticationPrincipal Usuario usuario) {
        return ResponseEntity.ok(ApiResponse.ok(aspiranteService.getDomicilio(usuario.getId())));
    }

    @Operation(summary = "Guardar domicilio familiar")
    @PutMapping("/domicilio")
    public ResponseEntity<ApiResponse<DomicilioFamiliar>> guardarDomicilio(
            @AuthenticationPrincipal Usuario usuario,
            @RequestBody DomicilioFamiliar datos) {
        return ResponseEntity.ok(ApiResponse.ok("Domicilio guardado",
                aspiranteService.guardarDomicilio(usuario.getId(), datos)));
    }

    // ==================== CONTACTO EMERGENCIA ====================

    @Operation(summary = "Obtener contacto de emergencia")
    @GetMapping("/contacto-emergencia")
    public ResponseEntity<ApiResponse<ContactoEmergencia>> getContactoEmergencia(
            @AuthenticationPrincipal Usuario usuario) {
        return ResponseEntity.ok(ApiResponse.ok(aspiranteService.getContactoEmergencia(usuario.getId())));
    }

    @Operation(summary = "Guardar contacto de emergencia")
    @PutMapping("/contacto-emergencia")
    public ResponseEntity<ApiResponse<ContactoEmergencia>> guardarContactoEmergencia(
            @AuthenticationPrincipal Usuario usuario,
            @RequestBody ContactoEmergencia datos) {
        return ResponseEntity.ok(ApiResponse.ok("Contacto de emergencia guardado",
                aspiranteService.guardarContactoEmergencia(usuario.getId(), datos)));
    }

    // ==================== ESCUELA PROCEDENCIA ====================

    @Operation(summary = "Obtener escuela de procedencia")
    @GetMapping("/escuela-procedencia")
    public ResponseEntity<ApiResponse<EscuelaProcedencia>> getEscuelaProcedencia(
            @AuthenticationPrincipal Usuario usuario) {
        return ResponseEntity.ok(ApiResponse.ok(aspiranteService.getEscuelaProcedencia(usuario.getId())));
    }

    @Operation(summary = "Guardar escuela de procedencia")
    @PutMapping("/escuela-procedencia")
    public ResponseEntity<ApiResponse<EscuelaProcedencia>> guardarEscuelaProcedencia(
            @AuthenticationPrincipal Usuario usuario,
            @RequestBody EscuelaProcedencia datos) {
        return ResponseEntity.ok(ApiResponse.ok("Escuela de procedencia guardada",
                aspiranteService.guardarEscuelaProcedencia(usuario.getId(), datos)));
    }

    // ==================== INFO CULTURAL ====================

    @Operation(summary = "Obtener información cultural")
    @GetMapping("/info-cultural")
    public ResponseEntity<ApiResponse<InfoCultural>> getInfoCultural(
            @AuthenticationPrincipal Usuario usuario) {
        return ResponseEntity.ok(ApiResponse.ok(aspiranteService.getInfoCultural(usuario.getId())));
    }

    @Operation(summary = "Guardar información cultural")
    @PutMapping("/info-cultural")
    public ResponseEntity<ApiResponse<InfoCultural>> guardarInfoCultural(
            @AuthenticationPrincipal Usuario usuario,
            @RequestBody InfoCultural datos) {
        return ResponseEntity.ok(ApiResponse.ok("Información cultural guardada",
                aspiranteService.guardarInfoCultural(usuario.getId(), datos)));
    }

    // ==================== INFO SOCIOECONÓMICA ====================

    @Operation(summary = "Obtener información socioeconómica")
    @GetMapping("/info-socioeconomica")
    public ResponseEntity<ApiResponse<InfoSocioeconomica>> getInfoSocioeconomica(
            @AuthenticationPrincipal Usuario usuario) {
        return ResponseEntity.ok(ApiResponse.ok(aspiranteService.getInfoSocioeconomica(usuario.getId())));
    }

    @Operation(summary = "Guardar información socioeconómica")
    @PutMapping("/info-socioeconomica")
    public ResponseEntity<ApiResponse<InfoSocioeconomica>> guardarInfoSocioeconomica(
            @AuthenticationPrincipal Usuario usuario,
            @RequestBody InfoSocioeconomica datos) {
        return ResponseEntity.ok(ApiResponse.ok("Información socioeconómica guardada",
                aspiranteService.guardarInfoSocioeconomica(usuario.getId(), datos)));
    }

    // ==================== CONFIRMACIÓN / SEDE ====================

    @Operation(summary = "Obtener confirmación de participación")
    @GetMapping("/confirmacion")
    public ResponseEntity<ApiResponse<ConfirmacionParticipacion>> getConfirmacion(
            @AuthenticationPrincipal Usuario usuario) {
        return ResponseEntity.ok(ApiResponse.ok(aspiranteService.getConfirmacion(usuario.getId())));
    }

    @Operation(summary = "Confirmar participación en examen")
    @PutMapping("/confirmacion")
    public ResponseEntity<ApiResponse<ConfirmacionParticipacion>> confirmarParticipacion(
            @AuthenticationPrincipal Usuario usuario,
            @RequestBody ConfirmacionParticipacion datos) {
        return ResponseEntity.ok(ApiResponse.ok("Participación confirmada",
                aspiranteService.confirmarParticipacion(usuario.getId(), datos)));
    }

    @Operation(summary = "Cancelar participación", description = "Cancela definitivamente la participación en el examen")
    @DeleteMapping("/confirmacion")
    public ResponseEntity<ApiResponse<Void>> cancelarParticipacion(
            @AuthenticationPrincipal Usuario usuario) {
        aspiranteService.cancelarParticipacion(usuario.getId());
        return ResponseEntity.ok(ApiResponse.ok("Participación cancelada definitivamente", null));
    }

    // ==================== SEDES ====================

    @Operation(summary = "Obtener sedes disponibles", description = "Lista las sedes de examen disponibles por estado")
    @GetMapping("/sedes")
    public ResponseEntity<ApiResponse<List<SedeExamen>>> getSedesDisponibles(
            @Parameter(description = "ID del estado") @RequestParam Long estadoId) {
        return ResponseEntity.ok(ApiResponse.ok(aspiranteService.getSedesDisponibles(estadoId)));
    }
}
