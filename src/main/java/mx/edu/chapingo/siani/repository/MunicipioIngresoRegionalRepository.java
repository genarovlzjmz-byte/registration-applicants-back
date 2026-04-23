package mx.edu.chapingo.siani.repository;

import mx.edu.chapingo.siani.domain.MunicipioIngresoRegional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface MunicipioIngresoRegionalRepository extends JpaRepository<MunicipioIngresoRegional, Long> {

    @Query("SELECT COUNT(m) > 0 FROM MunicipioIngresoRegional m " +
           "WHERE m.estado.id = :estadoId AND m.municipio.id = :municipioId AND m.activo = true")
    boolean existsByEstadoIdAndMunicipioIdAndActivoTrue(
            @Param("estadoId") Long estadoId,
            @Param("municipioId") Long municipioId);

    @Query("SELECT COUNT(m) > 0 FROM MunicipioIngresoRegional m " +
           "WHERE m.municipio.id = :municipioId AND m.activo = true")
    boolean existsByMunicipioIdAndActivoTrue(@Param("municipioId") Long municipioId);
}
