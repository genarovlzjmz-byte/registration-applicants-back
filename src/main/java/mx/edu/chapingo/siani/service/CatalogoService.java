package mx.edu.chapingo.siani.service;

import lombok.RequiredArgsConstructor;
import mx.edu.chapingo.siani.domain.*;
import mx.edu.chapingo.siani.dto.response.*;
import mx.edu.chapingo.siani.repository.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class CatalogoService {

    private final EstadoRepository estadoRepository;
    private final MunicipioRepository municipioRepository;
    private final LocalidadRepository localidadRepository;
    private final ModalidadRepository modalidadRepository;
    private final CodigoPostalRepository codigoPostalRepository;
    private final ColoniaRepository coloniaRepository;


    public List<EstadoResponse> listarEstados() {
        return estadoRepository.findByActivoTrueOrderByNombreAsc().stream()
                .map(e -> EstadoResponse.builder()
                        .id(e.getId())
                        .nombre(e.getNombre())
                        .abreviatura(e.getAbreviatura())
                        .build())
                .collect(Collectors.toList());
    }

    public List<MunicipioResponse> listarMunicipios(Long estadoId) {
        return municipioRepository.findByEstadoIdAndActivoTrueOrderByNombreAsc(estadoId).stream()
                .map(m -> MunicipioResponse.builder()
                        .id(m.getId())
                        .estadoId(estadoId)
                        .nombre(m.getNombre())
                        .build())
                .collect(Collectors.toList());
    }

    public List<LocalidadResponse> listarLocalidades(Long municipioId) {
        return localidadRepository.findByMunicipioIdAndActivoTrueOrderByNombreAsc(municipioId).stream()
                .map(l -> LocalidadResponse.builder()
                        .id(l.getId())
                        .municipioId(municipioId)
                        .nombre(l.getNombre())
                        .build())
                .collect(Collectors.toList());
    }

    public List<ModalidadResponse> listarModalidades() {
        return modalidadRepository.findByActivoTrueOrderByOrdenAsc().stream()
                .map(m -> ModalidadResponse.builder()
                        .id(m.getId())
                        .clave(m.getClave())
                        .nombre(m.getNombre())
                        .descripcion(m.getDescripcion())
                        .requiereValidacionRegional(m.getRequiereValidacionRegional())
                        .orden(m.getOrden())
                        .build())
                .collect(Collectors.toList());
    }

    public List<CodigoPostalResponse> listarCodigosPostales(Long municipioId) {
        return codigoPostalRepository.findByMunicipioIdAndActivoTrue(municipioId).stream()
                .map(cp -> CodigoPostalResponse.builder()
                        .id(cp.getId())
                        .codigo(cp.getCodigo())
                        .municipioId(municipioId)
                        .build())
                .collect(Collectors.toList());
    }

    public List<ColoniaResponse> listarColonias(Long codigoPostalId) {
        return coloniaRepository.findByCodigoPostalIdAndActivoTrueOrderByNombreAsc(codigoPostalId).stream()
                .map(c -> ColoniaResponse.builder()
                        .id(c.getId())
                        .codigoPostalId(codigoPostalId)
                        .nombre(c.getNombre())
                        .tipoAsentamiento(c.getTipoAsentamiento())
                        .zona(c.getZona())
                        .build())
                .collect(Collectors.toList());
    }

    public List<ColoniaResponse> buscarColoniasPorCp(String codigoPostal) {
        return coloniaRepository.findByCodigoPostalCodigoAndActivoTrueOrderByNombreAsc(codigoPostal).stream()
                .map(c -> ColoniaResponse.builder()
                        .id(c.getId())
                        .codigoPostalId(c.getCodigoPostal().getId())
                        .nombre(c.getNombre())
                        .tipoAsentamiento(c.getTipoAsentamiento())
                        .zona(c.getZona())
                        .build())
                .collect(Collectors.toList());
    }

    /**
     * Autocompletado de código postal: busca CPs que empiecen con el código ingresado
     * y trae sus colonias asociadas mediante JOIN.
     */
    public List<CodigoPostalConColoniasResponse> autocompletarCodigoPostal(String codigo) {
        List<CodigoPostal> codigosPostales = codigoPostalRepository.buscarPorCodigoStartingWith(codigo);

        return codigosPostales.stream()
                .map(cp -> {
                    List<ColoniaResponse> colonias = coloniaRepository
                            .findByCodigoPostalIdAndActivoTrueOrderByNombreAsc(cp.getId())
                            .stream()
                            .map(c -> ColoniaResponse.builder()
                                    .id(c.getId())
                                    .codigoPostalId(cp.getId())
                                    .nombre(c.getNombre())
                                    .tipoAsentamiento(c.getTipoAsentamiento())
                                    .zona(c.getZona())
                                    .build())
                            .collect(Collectors.toList());

                    return CodigoPostalConColoniasResponse.builder()
                            .id(cp.getId())
                            .codigo(cp.getCodigo())
                            .municipioId(cp.getMunicipio().getId())
                            .municipioNombre(cp.getMunicipio().getNombre())
                            .estadoId(cp.getMunicipio().getEstado().getId())
                            .estadoNombre(cp.getMunicipio().getEstado().getNombre())
                            .colonias(colonias)
                            .build();
                })
                .collect(Collectors.toList());
    }

    /**
     * Buscar código postal exacto con todas sus colonias.
     */
    public CodigoPostalConColoniasResponse buscarCodigoPostalConColonias(String codigo) {
        CodigoPostal cp = codigoPostalRepository.findByCodigoWithMunicipioAndEstado(codigo)
                .orElse(null);

        if (cp == null) {
            return null;
        }

        List<ColoniaResponse> colonias = coloniaRepository
                .findByCodigoPostalIdAndActivoTrueOrderByNombreAsc(cp.getId())
                .stream()
                .map(c -> ColoniaResponse.builder()
                        .id(c.getId())
                        .codigoPostalId(cp.getId())
                        .nombre(c.getNombre())
                        .tipoAsentamiento(c.getTipoAsentamiento())
                        .zona(c.getZona())
                        .build())
                .collect(Collectors.toList());

        return CodigoPostalConColoniasResponse.builder()
                .id(cp.getId())
                .codigo(cp.getCodigo())
                .municipioId(cp.getMunicipio().getId())
                .municipioNombre(cp.getMunicipio().getNombre())
                .estadoId(cp.getMunicipio().getEstado().getId())
                .estadoNombre(cp.getMunicipio().getEstado().getNombre())
                .colonias(colonias)
                .build();
    }
}
