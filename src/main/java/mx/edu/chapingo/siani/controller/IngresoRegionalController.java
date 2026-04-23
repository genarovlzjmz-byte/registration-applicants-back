package mx.edu.chapingo.siani.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import mx.edu.chapingo.siani.dto.response.ApiResponse;
import mx.edu.chapingo.siani.dto.response.ValidacionRegionalResponse;
import mx.edu.chapingo.siani.service.IngresoRegionalService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/ingreso-regional")
@RequiredArgsConstructor
@Tag(name = "Ingreso Regional", description = "API para validación de elegibilidad de ingreso regional")
public class IngresoRegionalController {

    private final IngresoRegionalService ingresoRegionalService;

    @Operation(
            summary = "Validar elegibilidad de ingreso regional",
            description = "Valida si un estado/municipio permite ingreso regional. Usado por el frontend para mostrar/ocultar la opción dinámicamente."
    )
    @GetMapping("/valida")
    public ResponseEntity<ApiResponse<ValidacionRegionalResponse>> validar(
            @Parameter(description = "ID del estado") @RequestParam Long estadoId,
            @Parameter(description = "ID del municipio") @RequestParam Long municipioId) {
        ValidacionRegionalResponse resultado = ingresoRegionalService.validarElegibilidad(estadoId, municipioId);
        return ResponseEntity.ok(ApiResponse.ok(resultado));
    }
}
