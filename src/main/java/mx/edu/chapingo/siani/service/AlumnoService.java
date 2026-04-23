package mx.edu.chapingo.siani.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import mx.edu.chapingo.siani.domain.*;
import mx.edu.chapingo.siani.dto.request.AlumnoRegistroRequest;
import mx.edu.chapingo.siani.dto.response.AlumnoCompletoDatosResponse;
import mx.edu.chapingo.siani.dto.response.AlumnoResponse;
import mx.edu.chapingo.siani.exception.*;
import mx.edu.chapingo.siani.repository.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AlumnoService {

    private final AlumnoRepository alumnoRepository;
    private final DatosPersonalesRepository datosPersonalesRepository;
    private final EstadoRepository estadoRepository;
    private final MunicipioRepository municipioRepository;
    private final LocalidadRepository localidadRepository;
    private final ModalidadRepository modalidadRepository;
    private final AuthService authService;
    private final IngresoRegionalService ingresoRegionalService;

    /**
     * Registro completo de alumno.
     * Incluye creación de usuario + datos del alumno en una transacción.
     */
    @Transactional
    public AlumnoResponse registrarAlumno(AlumnoRegistroRequest request) {
        log.info("Iniciando registro de alumno con CURP: {}", request.getCurp());

        // 1. Validar emails coinciden
        if (!request.getEmail().equalsIgnoreCase(request.getEmailConfirmacion())) {
            throw new BusinessException("Los correos electrónicos no coinciden");
        }

        // 2. Validar CURP no duplicada
        if (alumnoRepository.existsByCurp(request.getCurp().toUpperCase())) {
            throw new DuplicateResourceException("Alumno", "CURP", request.getCurp());
        }

        // 3. Validar email no duplicado
        if (alumnoRepository.existsByEmail(request.getEmail().toLowerCase())) {
            throw new DuplicateResourceException("Alumno", "email", request.getEmail());
        }

        // 4. Obtener entidades de catálogo
        Estado estado = estadoRepository.findById(request.getEstadoId())
                .orElseThrow(() -> new ResourceNotFoundException("Estado", "id", request.getEstadoId()));

        Municipio municipio = municipioRepository.findById(request.getMunicipioId())
                .orElseThrow(() -> new ResourceNotFoundException("Municipio", "id", request.getMunicipioId()));

        ModalidadIngreso modalidad = modalidadRepository.findById(request.getModalidadId())
                .orElseThrow(() -> new ResourceNotFoundException("Modalidad", "id", request.getModalidadId()));

        Localidad localidad = null;
        if (request.getLocalidadId() != null) {
            localidad = localidadRepository.findById(request.getLocalidadId())
                    .orElseThrow(() -> new ResourceNotFoundException("Localidad", "id", request.getLocalidadId()));
        }

        // 5. VALIDACIÓN BACKEND DE INGRESO REGIONAL (obligatoria)
        if ("REGIONAL".equals(request.getTipoIngreso())) {
            validarIngresoRegional(modalidad, request.getEstadoId(), request.getMunicipioId());
        }

        // 6. Si la modalidad requiere validación regional pero el tipo no es REGIONAL, rechazar
        if (modalidad.getRequiereValidacionRegional() && !"REGIONAL".equals(request.getTipoIngreso())) {
            throw new BusinessException(
                "La modalidad seleccionada requiere tipo de ingreso REGIONAL");
        }

        // 7. Crear usuario
        Usuario usuario = authService.crearUsuario(
                request.getCurp(),
                request.getEmail(),
                request.getPassword(),
                request.getPasswordConfirmacion()
        );

        // 8. Crear alumno
        Alumno alumno = Alumno.builder()
                .usuario(usuario)
                .curp(request.getCurp().toUpperCase())
                .nombre(request.getNombre().trim())
                .apellidoPaterno(request.getApellidoPaterno().trim())
                .apellidoMaterno(request.getApellidoMaterno() != null
                        ? request.getApellidoMaterno().trim() : null)
                .fechaNacimiento(request.getFechaNacimiento())
                .sexo(request.getSexo())
                .email(request.getEmail().toLowerCase())
                .emailConfirmacion(request.getEmailConfirmacion().toLowerCase())
                .telefono(request.getTelefono())
                .modalidad(modalidad)
                .tipoIngreso(request.getTipoIngreso())
                .escuelaProcedencia(request.getEscuelaProcedencia())
                .estado(estado)
                .municipio(municipio)
                .localidad(localidad)
                .aceptaTerminos(request.getAceptaTerminos())
                .estatus("REGISTRADO")
                .build();

        Alumno saved = alumnoRepository.save(alumno);
        log.info("Alumno registrado exitosamente. Folio: {}, CURP: {}", saved.getFolio(), saved.getCurp());

        return mapToResponse(saved);
    }

    /**
     * Validación backend obligatoria para ingreso regional.
     * NUNCA confiar solo en el frontend para esta regla.
     */
    private void validarIngresoRegional(ModalidadIngreso modalidad, Long estadoId, Long municipioId) {
        if (!modalidad.getRequiereValidacionRegional()) {
            throw new BusinessException(
                "La modalidad seleccionada no corresponde a ingreso regional");
        }

        boolean elegible = ingresoRegionalService.esElegibleParaIngresoRegional(estadoId, municipioId);

        if (!elegible) {
            throw new BusinessException(
                "La ubicación seleccionada NO es elegible para Ingreso Regional. " +
                "Solo aplica para el estado de Michoacán o municipios específicos habilitados.");
        }
    }

    @Transactional(readOnly = true)
    public List<AlumnoResponse> listarAlumnos() {
        return alumnoRepository.findAllByOrderByFechaRegistroDesc().stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public AlumnoResponse buscarPorId(Long id) {
        Alumno alumno = alumnoRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Alumno", "id", id));
        return mapToResponse(alumno);
    }

    @Transactional(readOnly = true)
    public AlumnoResponse buscarPorCurp(String curp) {
        Alumno alumno = alumnoRepository.findByCurp(curp.toUpperCase())
                .orElseThrow(() -> new ResourceNotFoundException("Alumno", "CURP", curp));
        return mapToResponse(alumno);
    }

    @Transactional(readOnly = true)
    public AlumnoCompletoDatosResponse getDatosPorUsuario(Long usuarioId) {
        Alumno alumno = alumnoRepository.findByUsuarioId(usuarioId)
                .orElseThrow(() -> new ResourceNotFoundException("Alumno", "usuario_id", usuarioId));

        // LEFT JOIN con datos_personales_aspirante
        var datosPersonales = datosPersonalesRepository.findByAlumnoId(alumno.getId()).orElse(null);

        return mapToCompletoResponse(alumno, datosPersonales);
    }

    private AlumnoCompletoDatosResponse mapToCompletoResponse(Alumno a, DatosPersonalesAspirante dp) {
        return AlumnoCompletoDatosResponse.builder()
                // Datos del Alumno
                .id(a.getId())
                .folio(a.getFolio())
                .curp(a.getCurp())
                .nombre(a.getNombre())
                .apellidoPaterno(a.getApellidoPaterno())
                .apellidoMaterno(a.getApellidoMaterno())
                .fechaNacimiento(dp != null ? dp.getFechaNacimiento() : a.getFechaNacimiento())
                .sexo(dp != null ? dp.getSexo() : a.getSexo())
                .email(a.getEmail())
                .telefono(a.getTelefono())
                .modalidadNombre(a.getModalidad().getNombre())
                .modalidadClave(a.getModalidad().getClave())
                .tipoIngreso(a.getTipoIngreso())
                .escuelaProcedencia(a.getEscuelaProcedencia())
                .estadoNombre(a.getEstado().getNombre())
                .estadoIdAlumno(a.getEstado() != null ? a.getEstado().getId() : null)
                .municipioNombre(a.getMunicipio().getNombre())
                .municipioIdAlumno(a.getMunicipio() != null ? a.getMunicipio().getId() : null)
                .localidadNombre(a.getLocalidad() != null ? a.getLocalidad().getNombre() : null)
                .estatus(a.getEstatus())
                .fechaRegistro(a.getFechaRegistro())
                // Datos Personales Aspirante (LEFT JOIN - puede ser null)
                .datosPersonalesId(dp != null ? dp.getId() : null)
                .entidadNacimientoId(dp != null ? dp.getEntidadNacimientoId() : null)
                .municipioNacimientoId(dp != null ? dp.getMunicipioNacimientoId() : null)
                .telefonoFijo(dp != null ? dp.getTelefonoFijo() : null)
                .telefonoCelular(dp != null ? dp.getTelefonoCelular() : null)
                .fueAlumnoChapingo(dp != null ? dp.getFueAlumnoChapingo() : null)
                .matriculaChapingo(dp != null ? dp.getMatriculaChapingo() : null)
                .nivelChapingo(dp != null ? dp.getNivelChapingo() : null)
                .gradoChapingo(dp != null ? dp.getGradoChapingo() : null)
                .datosPersonalesCompletado(dp != null && Boolean.TRUE.equals(dp.getCompletado()))
                .build();
    }

    private AlumnoResponse mapToResponse(Alumno a) {
        return AlumnoResponse.builder()
                .id(a.getId())
                .folio(a.getFolio())
                .curp(a.getCurp())
                .nombre(a.getNombre())
                .apellidoPaterno(a.getApellidoPaterno())
                .apellidoMaterno(a.getApellidoMaterno())
                .fechaNacimiento(a.getFechaNacimiento())
                .sexo(a.getSexo())
                .email(a.getEmail())
                .telefono(a.getTelefono())
                .modalidadNombre(a.getModalidad().getNombre())
                .modalidadClave(a.getModalidad().getClave())
                .tipoIngreso(a.getTipoIngreso())
                .escuelaProcedencia(a.getEscuelaProcedencia())
                .estadoNombre(a.getEstado().getNombre())
                .municipioNombre(a.getMunicipio().getNombre())
                .localidadNombre(a.getLocalidad() != null ? a.getLocalidad().getNombre() : null)
                .estatus(a.getEstatus())
                .fechaRegistro(a.getFechaRegistro())
                .build();
    }

    @Transactional(readOnly = true)
    public AlumnoResponse getAlumnoPorUsuario(Long usuarioId) {
        Alumno alumno = alumnoRepository.findByUsuarioId(usuarioId)
                .orElseThrow(() -> new ResourceNotFoundException("Alumno", "usuario_id", usuarioId));
        return mapToResponse(alumno);
    }

}
