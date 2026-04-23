package mx.edu.chapingo.siani.repository;

import mx.edu.chapingo.siani.domain.DatosPersonalesAspirante;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface DatosPersonalesRepository extends JpaRepository<DatosPersonalesAspirante, Long> {
    Optional<DatosPersonalesAspirante> findByAlumnoId(Long alumnoId);
}
