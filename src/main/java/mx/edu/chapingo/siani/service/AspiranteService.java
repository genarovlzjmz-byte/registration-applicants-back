package mx.edu.chapingo.siani.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import mx.edu.chapingo.siani.domain.*;
import mx.edu.chapingo.siani.exception.BusinessException;
import mx.edu.chapingo.siani.exception.ResourceNotFoundException;
import mx.edu.chapingo.siani.repository.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class AspiranteService {

    private final AlumnoRepository alumnoRepository;
    private final DatosPersonalesRepository datosPersonalesRepo;
    private final DatosPadresRepository datosPadresRepo;
    private final DomicilioFamiliarRepository domicilioRepo;
    private final ContactoEmergenciaRepository contactoRepo;
    private final EscuelaProcedenciaRepository escuelaRepo;
    private final InfoCulturalRepository infoCulturalRepo;
    private final InfoSocioeconomicaRepository infoSocioRepo;
    private final ConfirmacionParticipacionRepository confirmacionRepo;
    private final SedeExamenRepository sedeRepo;

    // ===================== HELPERS =====================

    private Alumno getAlumnoByUsuarioId(Long usuarioId) {
        return alumnoRepository.findByUsuarioId(usuarioId)
                .orElseThrow(() -> new ResourceNotFoundException("Alumno no encontrado para usuario: " + usuarioId));
    }

    // ===================== ESTADO DE SECCIONES =====================

    @Transactional(readOnly = true)
    public Map<String, String> getEstadoSecciones(Long usuarioId) {
        Alumno alumno = getAlumnoByUsuarioId(usuarioId);
        Long aid = alumno.getId();

        Map<String, String> estados = new LinkedHashMap<>();
        estados.put("datosPersonales", getEstado(datosPersonalesRepo.findByAlumnoId(aid).map(DatosPersonalesAspirante::getCompletado).orElse(false)));
        estados.put("datosPadres", getEstado(datosPadresRepo.findByAlumnoId(aid).map(DatosPadres::getCompletado).orElse(false)));
        estados.put("domicilio", getEstado(domicilioRepo.findByAlumnoId(aid).map(DomicilioFamiliar::getCompletado).orElse(false)));
        estados.put("contactoEmergencia", getEstado(contactoRepo.findByAlumnoId(aid).map(ContactoEmergencia::getCompletado).orElse(false)));
        estados.put("escuelaProcedencia", getEstado(escuelaRepo.findByAlumnoId(aid).map(EscuelaProcedencia::getCompletado).orElse(false)));
        estados.put("infoCultural", getEstado(infoCulturalRepo.findByAlumnoId(aid).map(InfoCultural::getCompletado).orElse(false)));

        // Socioeconómica tiene sub-secciones, podría estar parcial
        var socioOpt = infoSocioRepo.findByAlumnoId(aid);
        if (socioOpt.isEmpty()) {
            estados.put("infoSocioeconomica", "PENDIENTE");
        } else {
            InfoSocioeconomica socio = socioOpt.get();
            if (socio.getCompletado()) {
                estados.put("infoSocioeconomica", "COMPLETADO");
            } else {
                boolean algunaCompleta = Boolean.TRUE.equals(socio.getSeccion1Completa()) ||
                        Boolean.TRUE.equals(socio.getSeccion2Completa()) ||
                        Boolean.TRUE.equals(socio.getSeccion3Completa());
                estados.put("infoSocioeconomica", algunaCompleta ? "PARCIAL" : "PENDIENTE");
            }
        }

        estados.put("confirmacion", getEstado(confirmacionRepo.findByAlumnoId(aid).map(ConfirmacionParticipacion::getCompletado).orElse(false)));

        return estados;
    }

    private String getEstado(Boolean completado) {
        return Boolean.TRUE.equals(completado) ? "COMPLETADO" : "PENDIENTE";
    }

    // ===================== DATOS PERSONALES =====================

    @Transactional(readOnly = true)
    public DatosPersonalesAspirante getDatosPersonales(Long usuarioId) {
        Alumno alumno = getAlumnoByUsuarioId(usuarioId);
        return datosPersonalesRepo.findByAlumnoId(alumno.getId())
                .orElseGet(() -> {
                    DatosPersonalesAspirante dp = new DatosPersonalesAspirante();
                    dp.setAlumno(alumno);
                    return dp;
                });
    }

    @Transactional
    public DatosPersonalesAspirante guardarDatosPersonales(Long usuarioId, DatosPersonalesAspirante datos) {
        Alumno alumno = getAlumnoByUsuarioId(usuarioId);
        DatosPersonalesAspirante existing = datosPersonalesRepo.findByAlumnoId(alumno.getId())
                .orElseGet(() -> DatosPersonalesAspirante.builder().alumno(alumno).build());

        existing.setFechaNacimiento(datos.getFechaNacimiento());
        existing.setEntidadNacimientoId(datos.getEntidadNacimientoId());
        existing.setMunicipioNacimientoId(datos.getMunicipioNacimientoId());
        existing.setSexo(datos.getSexo());
        existing.setTelefonoFijo(datos.getTelefonoFijo());
        existing.setTelefonoCelular(datos.getTelefonoCelular());
        existing.setFueAlumnoChapingo(datos.getFueAlumnoChapingo());
        existing.setMatriculaChapingo(datos.getMatriculaChapingo());
        existing.setNivelChapingo(datos.getNivelChapingo());
        existing.setGradoChapingo(datos.getGradoChapingo());
        existing.setCompletado(true);
        existing.setUpdatedAt(LocalDateTime.now());

        log.info("Guardando datos personales para alumno {}", alumno.getId());
        return datosPersonalesRepo.save(existing);
    }

    // ===================== DATOS PADRES =====================

    @Transactional(readOnly = true)
    public DatosPadres getDatosPadres(Long usuarioId) {
        Alumno alumno = getAlumnoByUsuarioId(usuarioId);
        return datosPadresRepo.findByAlumnoId(alumno.getId())
                .orElseGet(() -> { DatosPadres dp = new DatosPadres(); dp.setAlumno(alumno); return dp; });
    }

    @Transactional
    public DatosPadres guardarDatosPadres(Long usuarioId, DatosPadres datos) {
        Alumno alumno = getAlumnoByUsuarioId(usuarioId);
        DatosPadres existing = datosPadresRepo.findByAlumnoId(alumno.getId())
                .orElseGet(() -> DatosPadres.builder().alumno(alumno).build());

        existing.setPadreLabora(datos.getPadreLabora());
        existing.setPadreNombre(datos.getPadreNombre());
        existing.setPadreApellidoPaterno(datos.getPadreApellidoPaterno());
        existing.setPadreApellidoMaterno(datos.getPadreApellidoMaterno());
        existing.setPadreOcupacion(datos.getPadreOcupacion());
        existing.setPadreIngresoMensual(datos.getPadreIngresoMensual());
        existing.setMadreLabora(datos.getMadreLabora());
        existing.setMadreNombre(datos.getMadreNombre());
        existing.setMadreApellidoPaterno(datos.getMadreApellidoPaterno());
        existing.setMadreApellidoMaterno(datos.getMadreApellidoMaterno());
        existing.setMadreOcupacion(datos.getMadreOcupacion());
        existing.setMadreIngresoMensual(datos.getMadreIngresoMensual());
        existing.setCompletado(true);
        existing.setUpdatedAt(LocalDateTime.now());

        return datosPadresRepo.save(existing);
    }

    // ===================== DOMICILIO =====================

    @Transactional(readOnly = true)
    public DomicilioFamiliar getDomicilio(Long usuarioId) {
        Alumno alumno = getAlumnoByUsuarioId(usuarioId);
        return domicilioRepo.findByAlumnoId(alumno.getId())
                .orElseGet(() -> { DomicilioFamiliar d = new DomicilioFamiliar(); d.setAlumno(alumno); return d; });
    }

    @Transactional
    public DomicilioFamiliar guardarDomicilio(Long usuarioId, DomicilioFamiliar datos) {
        Alumno alumno = getAlumnoByUsuarioId(usuarioId);
        DomicilioFamiliar existing = domicilioRepo.findByAlumnoId(alumno.getId())
                .orElseGet(() -> DomicilioFamiliar.builder().alumno(alumno).build());

        existing.setCodigoPostal(datos.getCodigoPostal());
        existing.setColonia(datos.getColonia());
        existing.setCalle(datos.getCalle());
        existing.setNumExterior(datos.getNumExterior());
        existing.setNumInterior(datos.getNumInterior());
        existing.setManzana(datos.getManzana());
        existing.setLote(datos.getLote());
        existing.setEntreCalle1(datos.getEntreCalle1());
        existing.setEntreCalle2(datos.getEntreCalle2());
        existing.setReferencia(datos.getReferencia());
        existing.setCompletado(true);
        existing.setUpdatedAt(LocalDateTime.now());

        return domicilioRepo.save(existing);
    }

    // ===================== CONTACTO EMERGENCIA =====================

    @Transactional(readOnly = true)
    public ContactoEmergencia getContactoEmergencia(Long usuarioId) {
        Alumno alumno = getAlumnoByUsuarioId(usuarioId);
        return contactoRepo.findByAlumnoId(alumno.getId())
                .orElseGet(() -> { ContactoEmergencia c = new ContactoEmergencia(); c.setAlumno(alumno); return c; });
    }

    @Transactional
    public ContactoEmergencia guardarContactoEmergencia(Long usuarioId, ContactoEmergencia datos) {
        Alumno alumno = getAlumnoByUsuarioId(usuarioId);
        ContactoEmergencia existing = contactoRepo.findByAlumnoId(alumno.getId())
                .orElseGet(() -> ContactoEmergencia.builder().alumno(alumno).build());

        existing.setNombre(datos.getNombre());
        existing.setApellidoPaterno(datos.getApellidoPaterno());
        existing.setApellidoMaterno(datos.getApellidoMaterno());
        existing.setTelefonoCelular(datos.getTelefonoCelular());
        existing.setCompletado(true);
        existing.setUpdatedAt(LocalDateTime.now());

        return contactoRepo.save(existing);
    }

    // ===================== ESCUELA PROCEDENCIA =====================

    @Transactional(readOnly = true)
    public EscuelaProcedencia getEscuelaProcedencia(Long usuarioId) {
        Alumno alumno = getAlumnoByUsuarioId(usuarioId);
        return escuelaRepo.findByAlumnoId(alumno.getId())
                .orElseGet(() -> { EscuelaProcedencia e = new EscuelaProcedencia(); e.setAlumno(alumno); return e; });
    }

    @Transactional
    public EscuelaProcedencia guardarEscuelaProcedencia(Long usuarioId, EscuelaProcedencia datos) {
        Alumno alumno = getAlumnoByUsuarioId(usuarioId);
        EscuelaProcedencia existing = escuelaRepo.findByAlumnoId(alumno.getId())
                .orElseGet(() -> EscuelaProcedencia.builder().alumno(alumno).build());

        existing.setTipoSistemaEducativo(datos.getTipoSistemaEducativo());
        existing.setClaveCCT(datos.getClaveCCT());
        existing.setNombreEscuela(datos.getNombreEscuela());
        existing.setEstadoEscuelaId(datos.getEstadoEscuelaId());
        existing.setMunicipioEscuelaId(datos.getMunicipioEscuelaId());
        existing.setLocalidadEscuelaId(datos.getLocalidadEscuelaId());
        existing.setCodigoPostalEscuela(datos.getCodigoPostalEscuela());
        existing.setColoniaEscuela(datos.getColoniaEscuela());
        existing.setCalleEscuela(datos.getCalleEscuela());
        existing.setNumExtEscuela(datos.getNumExtEscuela());
        existing.setTipoEscuela(datos.getTipoEscuela());
        existing.setClasificacionEducativa(datos.getClasificacionEducativa());
        existing.setCompletado(true);
        existing.setUpdatedAt(LocalDateTime.now());

        return escuelaRepo.save(existing);
    }

    // ===================== INFO CULTURAL =====================

    @Transactional(readOnly = true)
    public InfoCultural getInfoCultural(Long usuarioId) {
        Alumno alumno = getAlumnoByUsuarioId(usuarioId);
        return infoCulturalRepo.findByAlumnoId(alumno.getId())
                .orElseGet(() -> { InfoCultural ic = new InfoCultural(); ic.setAlumno(alumno); return ic; });
    }

    @Transactional
    public InfoCultural guardarInfoCultural(Long usuarioId, InfoCultural datos) {
        Alumno alumno = getAlumnoByUsuarioId(usuarioId);
        InfoCultural existing = infoCulturalRepo.findByAlumnoId(alumno.getId())
                .orElseGet(() -> InfoCultural.builder().alumno(alumno).build());

        // Indígena
        existing.setPertencePuebloIndigena(datos.getPertencePuebloIndigena());
        existing.setPuebloIndigena(datos.getPuebloIndigena());
        existing.setLenguaMaternaHabla(datos.getLenguaMaternaHabla());
        existing.setLenguaMaternaEscribe(datos.getLenguaMaternaEscribe());
        existing.setLenguaMaternaComprende(datos.getLenguaMaternaComprende());
        existing.setLenguaMaternaNinguna(datos.getLenguaMaternaNinguna());
        existing.setFamiliarIndigena(datos.getFamiliarIndigena());
        existing.setFamiliarIndigenaPadre(datos.getFamiliarIndigenaPadre());
        existing.setFamiliarIndigenaMadre(datos.getFamiliarIndigenaMadre());
        existing.setFamiliarIndigenaAbuelos(datos.getFamiliarIndigenaAbuelos());
        // Afromexicana
        existing.setAfromexicano(datos.getAfromexicano());
        existing.setIdentificacionAfromexicana(datos.getIdentificacionAfromexicana());
        existing.setVinculosAfromexicanos(datos.getVinculosAfromexicanos());
        existing.setRegionAfromexicana(datos.getRegionAfromexicana());
        // Discapacidad
        existing.setTieneDiscapacidad(datos.getTieneDiscapacidad());
        existing.setDiscapacidadFisicaMotriz(datos.getDiscapacidadFisicaMotriz());
        existing.setDiscapacidadIntelectual(datos.getDiscapacidadIntelectual());
        existing.setDiscapacidadAuditivaHipoacusia(datos.getDiscapacidadAuditivaHipoacusia());
        existing.setDiscapacidadAuditivaSordera(datos.getDiscapacidadAuditivaSordera());
        existing.setDiscapacidadVisualBaja(datos.getDiscapacidadVisualBaja());
        existing.setDiscapacidadVisualCeguera(datos.getDiscapacidadVisualCeguera());
        existing.setDiscapacidadNinguna(datos.getDiscapacidadNinguna());

        existing.setCompletado(true);
        existing.setUpdatedAt(LocalDateTime.now());

        return infoCulturalRepo.save(existing);
    }

    // ===================== INFO SOCIOECONÓMICA =====================

    @Transactional(readOnly = true)
    public InfoSocioeconomica getInfoSocioeconomica(Long usuarioId) {
        Alumno alumno = getAlumnoByUsuarioId(usuarioId);
        return infoSocioRepo.findByAlumnoId(alumno.getId())
                .orElseGet(() -> { InfoSocioeconomica is = new InfoSocioeconomica(); is.setAlumno(alumno); return is; });
    }

    @Transactional
    public InfoSocioeconomica guardarInfoSocioeconomica(Long usuarioId, InfoSocioeconomica datos) {
        Alumno alumno = getAlumnoByUsuarioId(usuarioId);
        InfoSocioeconomica existing = infoSocioRepo.findByAlumnoId(alumno.getId())
                .orElseGet(() -> InfoSocioeconomica.builder().alumno(alumno).build());

        // Copiar todos los campos
        existing.setPromedioGeneral(datos.getPromedioGeneral());
        existing.setBecaEscolar(datos.getBecaEscolar());
        existing.setTipoBeca(datos.getTipoBeca());
        existing.setRespParentesco(datos.getRespParentesco());
        existing.setRespNombre(datos.getRespNombre());
        existing.setRespOcupacion(datos.getRespOcupacion());
        existing.setRespIngresoMensual(datos.getRespIngresoMensual());
        existing.setRespEscolaridad(datos.getRespEscolaridad());
        existing.setParejaOcupacion(datos.getParejaOcupacion());
        existing.setParejaIngresoMensual(datos.getParejaIngresoMensual());
        existing.setParejaEscolaridad(datos.getParejaEscolaridad());
        existing.setOtrosIngresosMonto(datos.getOtrosIngresosMonto());
        existing.setOtrosIngresosFuente(datos.getOtrosIngresosFuente());
        existing.setViviendaTipo(datos.getViviendaTipo());
        existing.setViviendaPropiedad(datos.getViviendaPropiedad());
        existing.setViviendaMaterialParedes(datos.getViviendaMaterialParedes());
        existing.setViviendaMaterialTecho(datos.getViviendaMaterialTecho());
        existing.setViviendaMaterialPiso(datos.getViviendaMaterialPiso());
        existing.setViviendaNumCuartos(datos.getViviendaNumCuartos());
        existing.setViviendaNumPersonas(datos.getViviendaNumPersonas());
        existing.setTieneAguaPotable(datos.getTieneAguaPotable());
        existing.setTieneEnergiaElectrica(datos.getTieneEnergiaElectrica());
        existing.setTieneDrenaje(datos.getTieneDrenaje());
        existing.setTieneInternet(datos.getTieneInternet());
        existing.setTieneVehiculo(datos.getTieneVehiculo());
        existing.setTieneComputadora(datos.getTieneComputadora());
        existing.setTieneTelefono(datos.getTieneTelefono());
        existing.setSeccion1Completa(datos.getSeccion1Completa());
        existing.setSeccion2Completa(datos.getSeccion2Completa());
        existing.setSeccion3Completa(datos.getSeccion3Completa());
        existing.setSeccion4Completa(datos.getSeccion4Completa());
        existing.setSeccion5Completa(datos.getSeccion5Completa());
        existing.setSeccion6Completa(datos.getSeccion6Completa());

        // Si todas las sub-secciones están completas, marcar como completado
        boolean todasCompletas = Boolean.TRUE.equals(datos.getSeccion1Completa()) &&
                Boolean.TRUE.equals(datos.getSeccion2Completa()) &&
                Boolean.TRUE.equals(datos.getSeccion3Completa()) &&
                Boolean.TRUE.equals(datos.getSeccion4Completa()) &&
                Boolean.TRUE.equals(datos.getSeccion5Completa()) &&
                Boolean.TRUE.equals(datos.getSeccion6Completa());
        existing.setCompletado(todasCompletas);
        existing.setUpdatedAt(LocalDateTime.now());

        return infoSocioRepo.save(existing);
    }

    // ===================== CONFIRMACIÓN / CANCELACIÓN =====================

    @Transactional(readOnly = true)
    public ConfirmacionParticipacion getConfirmacion(Long usuarioId) {
        Alumno alumno = getAlumnoByUsuarioId(usuarioId);
        return confirmacionRepo.findByAlumnoId(alumno.getId())
                .orElseGet(() -> { ConfirmacionParticipacion c = new ConfirmacionParticipacion(); c.setAlumno(alumno); return c; });
    }

    @Transactional
    public ConfirmacionParticipacion confirmarParticipacion(Long usuarioId, ConfirmacionParticipacion datos) {
        Alumno alumno = getAlumnoByUsuarioId(usuarioId);
        ConfirmacionParticipacion existing = confirmacionRepo.findByAlumnoId(alumno.getId())
                .orElseGet(() -> ConfirmacionParticipacion.builder().alumno(alumno).build());

        if (Boolean.TRUE.equals(existing.getCancelado())) {
            throw new BusinessException("Tu participación ya fue cancelada definitivamente. No es posible reactivarla.");
        }

        existing.setConfirmado(true);
        existing.setEstadoSedeId(datos.getEstadoSedeId());
        existing.setSedeId(datos.getSedeId());
        existing.setEscuelaSede(datos.getEscuelaSede());
        existing.setFechaConfirmacion(LocalDateTime.now());
        existing.setCompletado(true);
        existing.setUpdatedAt(LocalDateTime.now());

        log.info("Alumno {} confirmó participación, sede: {}", alumno.getId(), datos.getSedeId());
        return confirmacionRepo.save(existing);
    }

    @Transactional
    public void cancelarParticipacion(Long usuarioId) {
        Alumno alumno = getAlumnoByUsuarioId(usuarioId);
        ConfirmacionParticipacion existing = confirmacionRepo.findByAlumnoId(alumno.getId())
                .orElseGet(() -> ConfirmacionParticipacion.builder().alumno(alumno).build());

        if (Boolean.TRUE.equals(existing.getCancelado())) {
            throw new BusinessException("La participación ya fue cancelada anteriormente.");
        }

        existing.setCancelado(true);
        existing.setConfirmado(false);
        existing.setFechaCancelacion(LocalDateTime.now());
        existing.setCompletado(false);
        existing.setUpdatedAt(LocalDateTime.now());

        // Actualizar estatus del alumno
        alumno.setEstatus("CANCELADO");
        alumnoRepository.save(alumno);

        log.warn("Alumno {} CANCELÓ DEFINITIVAMENTE su participación", alumno.getId());
        confirmacionRepo.save(existing);
    }

    // ===================== SEDES =====================

    @Transactional(readOnly = true)
    public java.util.List<SedeExamen> getSedesDisponibles(Long estadoId) {
        return sedeRepo.findByEstadoIdAndActivoTrue(estadoId);
    }
}
