package mx.edu.chapingo.siani.repository;

import mx.edu.chapingo.siani.domain.Localidad;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface LocalidadRepository extends JpaRepository<Localidad, Long> {
    List<Localidad> findByMunicipioIdAndActivoTrueOrderByNombreAsc(Long municipioId);
}
