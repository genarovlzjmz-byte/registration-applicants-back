package mx.edu.chapingo.siani.service;

import lombok.RequiredArgsConstructor;
import mx.edu.chapingo.siani.domain.Estado;
import mx.edu.chapingo.siani.domain.Municipio;
import mx.edu.chapingo.siani.dto.response.ValidacionRegionalResponse;
import mx.edu.chapingo.siani.exception.ResourceNotFoundException;
import mx.edu.chapingo.siani.repository.EstadoRepository;
import mx.edu.chapingo.siani.repository.MunicipioIngresoRegionalRepository;
import mx.edu.chapingo.siani.repository.MunicipioRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Servicio que implementa la REGLA DE NEGOCIO ESPECIAL:
 *
 * La opción de Ingreso Regional solo debe mostrarse cuando:
 * 1. El estado seleccionado sea Michoacán (sede Morelia)
 * 2. O cuando el municipio pertenezca a la tabla municipios_ingreso_regional
 *
 * Esta validación se ejecuta SIEMPRE en backend, independientemente del frontend.
 */
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class IngresoRegionalService {

    private static final String ESTADO_MICHOACAN = "Michoacán";

    private final MunicipioIngresoRegionalRepository mirRepository;
    private final EstadoRepository estadoRepository;
    private final MunicipioRepository municipioRepository;

    /**
     * Valida si un estado/municipio es elegible para ingreso regional.
     * Regla: Michoacán completo + municipios específicos en tabla configurable.
     */
    public ValidacionRegionalResponse validarElegibilidad(Long estadoId, Long municipioId) {
        Estado estado = estadoRepository.findById(estadoId)
                .orElseThrow(() -> new ResourceNotFoundException("Estado", "id", estadoId));

        Municipio municipio = municipioRepository.findById(municipioId)
                .orElseThrow(() -> new ResourceNotFoundException("Municipio", "id", municipioId));

        boolean elegible = esElegibleParaIngresoRegional(estadoId, municipioId, estado.getNombre());

        String mensaje = elegible
                ? "La ubicación seleccionada es elegible para Ingreso Regional."
                : "La ubicación seleccionada NO es elegible para Ingreso Regional.";

        return ValidacionRegionalResponse.builder()
                .elegible(elegible)
                .estadoId(estadoId)
                .municipioId(municipioId)
                .estadoNombre(estado.getNombre())
                .municipioNombre(municipio.getNombre())
                .mensaje(mensaje)
                .build();
    }

    /**
     * Validación interna reutilizable por AlumnoService.
     * Retorna true si el municipio/estado permite ingreso regional.
     */
    public boolean esElegibleParaIngresoRegional(Long estadoId, Long municipioId, String estadoNombre) {
        // Regla 1: Todo Michoacán es elegible
        if (ESTADO_MICHOACAN.equalsIgnoreCase(estadoNombre)) {
            return true;
        }

        // Regla 2: Municipios específicos en tabla configurable
        return mirRepository.existsByEstadoIdAndMunicipioIdAndActivoTrue(estadoId, municipioId);
    }

    /**
     * Versión simplificada que busca el nombre del estado internamente.
     */
    public boolean esElegibleParaIngresoRegional(Long estadoId, Long municipioId) {
        Estado estado = estadoRepository.findById(estadoId)
                .orElseThrow(() -> new ResourceNotFoundException("Estado", "id", estadoId));
        return esElegibleParaIngresoRegional(estadoId, municipioId, estado.getNombre());
    }
}
