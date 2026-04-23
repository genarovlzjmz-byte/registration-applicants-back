package mx.edu.chapingo.siani.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import mx.edu.chapingo.siani.domain.Usuario;
import mx.edu.chapingo.siani.dto.request.AlumnoRegistroRequest;
import mx.edu.chapingo.siani.dto.response.AlumnoCompletoDatosResponse;
import mx.edu.chapingo.siani.dto.response.AlumnoResponse;
import mx.edu.chapingo.siani.dto.response.ApiResponse;
import mx.edu.chapingo.siani.service.AlumnoService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/alumnos")
@RequiredArgsConstructor
@Tag(name = "Alumnos", description = "API para gestión de registro de aspirantes")
public class AlumnoController {

    private final AlumnoService alumnoService;

    @Operation(summary = "Registrar nuevo aspirante", description = "Permite registrar un nuevo aspirante en el sistema. Genera un folio único.")
    @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "201", description = "Aspirante registrado exitosamente")
    @PostMapping
    public ResponseEntity<ApiResponse<AlumnoResponse>> registrar(
            @Valid @RequestBody AlumnoRegistroRequest request) {
        AlumnoResponse alumno = alumnoService.registrarAlumno(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.ok("Alumno registrado exitosamente. Folio: " + alumno.getFolio(), alumno));
    }

    @Operation(summary = "Listar todos los aspirantes", description = "Obtiene la lista de todos los aspirantes registrados. Requiere autenticación.")
    @GetMapping
    public ResponseEntity<ApiResponse<List<AlumnoResponse>>> listar() {
        return ResponseEntity.ok(ApiResponse.ok(alumnoService.listarAlumnos()));
    }

    @Operation(summary = "Buscar aspirante por ID", description = "Obtiene los datos de un aspirante por su ID. Requiere autenticación.")
    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<AlumnoResponse>> buscarPorId(
            @Parameter(description = "ID del aspirante") @PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.ok(alumnoService.buscarPorId(id)));
    }

    @Operation(summary = "Buscar aspirante por CURP", description = "Obtiene los datos de un aspirante por su CURP. Requiere autenticación.")
    @GetMapping("/curp/{curp}")
    public ResponseEntity<ApiResponse<AlumnoResponse>> buscarPorCurp(
            @Parameter(description = "CURP del aspirante") @PathVariable String curp) {
        return ResponseEntity.ok(ApiResponse.ok(alumnoService.buscarPorCurp(curp)));
    }

    // ==================== DATOS DEL ALUMNO POR USUARIO ====================

    @Operation(summary = "Obtener datos del alumno por usuario", description = "Obtiene los datos del alumno y datos personales asociados al usuario autenticado (LEFT JOIN)")
    @GetMapping("/datos-por-usuario")
    public ResponseEntity<ApiResponse<AlumnoCompletoDatosResponse>> getDatosAlumnoPorUsuario(
            @AuthenticationPrincipal Usuario usuario) {
        return ResponseEntity.ok(ApiResponse.ok(alumnoService.getDatosPorUsuario(usuario.getId())));
    }

    @Operation(summary = "Obtener alumno por usuario", description = "Obtiene los datos básicos del alumno asociado al usuario autenticado")
    @GetMapping("/getAlumnoPorUsuario")
    public ResponseEntity<ApiResponse<AlumnoResponse>> getAlumnoPorUsuario(
            @AuthenticationPrincipal Usuario usuario) {
        return ResponseEntity.ok(ApiResponse.ok(alumnoService.getAlumnoPorUsuario(usuario.getId())));
    }

}
