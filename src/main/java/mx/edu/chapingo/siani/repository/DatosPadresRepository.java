package mx.edu.chapingo.siani.repository;

import mx.edu.chapingo.siani.domain.DatosPadres;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface DatosPadresRepository extends JpaRepository<DatosPadres, Long> {
    Optional<DatosPadres> findByAlumnoId(Long alumnoId);
}
