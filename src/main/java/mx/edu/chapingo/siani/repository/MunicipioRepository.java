package mx.edu.chapingo.siani.repository;

import mx.edu.chapingo.siani.domain.Municipio;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface MunicipioRepository extends JpaRepository<Municipio, Long> {
    List<Municipio> findByEstadoIdAndActivoTrueOrderByNombreAsc(Long estadoId);
}
