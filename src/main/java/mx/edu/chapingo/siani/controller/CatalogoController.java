package mx.edu.chapingo.siani.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import mx.edu.chapingo.siani.dto.response.*;
import mx.edu.chapingo.siani.service.CatalogoService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/catalogos")
@RequiredArgsConstructor
@Tag(name = "Catálogos", description = "API para consulta de catálogos geográficos y modalidades")
public class CatalogoController {

    private final CatalogoService catalogoService;

    @Operation(summary = "Listar estados", description = "Obtiene la lista de todos los estados de México")
    @GetMapping("/estados")
    public ResponseEntity<ApiResponse<List<EstadoResponse>>> listarEstados() {
        return ResponseEntity.ok(ApiResponse.ok(catalogoService.listarEstados()));
    }

    @Operation(summary = "Listar municipios por estado", description = "Obtiene la lista de municipios de un estado específico")
    @GetMapping("/municipios")
    public ResponseEntity<ApiResponse<List<MunicipioResponse>>> listarMunicipios(
            @Parameter(description = "ID del estado") @RequestParam Long estadoId) {
        return ResponseEntity.ok(ApiResponse.ok(catalogoService.listarMunicipios(estadoId)));
    }

    @Operation(summary = "Listar localidades por municipio", description = "Obtiene la lista de localidades de un municipio específico")
    @GetMapping("/localidades")
    public ResponseEntity<ApiResponse<List<LocalidadResponse>>> listarLocalidades(
            @Parameter(description = "ID del municipio") @RequestParam Long municipioId) {
        return ResponseEntity.ok(ApiResponse.ok(catalogoService.listarLocalidades(municipioId)));
    }

    @Operation(summary = "Listar modalidades de ingreso", description = "Obtiene la lista de todas las modalidades de ingreso disponibles")
    @GetMapping("/modalidades")
    public ResponseEntity<ApiResponse<List<ModalidadResponse>>> listarModalidades() {
        return ResponseEntity.ok(ApiResponse.ok(catalogoService.listarModalidades()));
    }

    @GetMapping("/codigos-postales")
    public ResponseEntity<ApiResponse<List<CodigoPostalResponse>>> listarCodigosPostales(
            @RequestParam Long municipioId) {
        return ResponseEntity.ok(ApiResponse.ok(catalogoService.listarCodigosPostales(municipioId)));
    }

    @GetMapping("/colonias")
    public ResponseEntity<ApiResponse<List<ColoniaResponse>>> listarColonias(
            @RequestParam Long codigoPostalId) {
        return ResponseEntity.ok(ApiResponse.ok(catalogoService.listarColonias(codigoPostalId)));
    }

    @GetMapping("/colonias-por-cp")
    public ResponseEntity<ApiResponse<List<ColoniaResponse>>> buscarColoniasPorCp(
            @RequestParam String cp) {
        return ResponseEntity.ok(ApiResponse.ok(catalogoService.buscarColoniasPorCp(cp)));
    }

    @Operation(summary = "Autocompletar código postal",
               description = "Busca códigos postales que empiecen con el valor ingresado y retorna sus colonias asociadas")
    @GetMapping("/codigo-postal/autocomplete")
    public ResponseEntity<ApiResponse<List<CodigoPostalConColoniasResponse>>> autocompletarCodigoPostal(
            @Parameter(description = "Código postal parcial o completo") @RequestParam String codigo) {
        return ResponseEntity.ok(ApiResponse.ok(catalogoService.autocompletarCodigoPostal(codigo)));
    }

    @Operation(summary = "Buscar código postal con colonias",
               description = "Busca un código postal exacto y retorna todas sus colonias, municipio y estado")
    @GetMapping(" ")
    public ResponseEntity<ApiResponse<CodigoPostalConColoniasResponse>> buscarCodigoPostalConColonias(
            @Parameter(description = "Código postal exacto (5 dígitos)") @PathVariable String codigo) {
        CodigoPostalConColoniasResponse response = catalogoService.buscarCodigoPostalConColonias(codigo);
        if (response == null) {
            return ResponseEntity.ok(ApiResponse.error("Código postal no encontrado"));
        }
        return ResponseEntity.ok(ApiResponse.ok(response));
    }
}
