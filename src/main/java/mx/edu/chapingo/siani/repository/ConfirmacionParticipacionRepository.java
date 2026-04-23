package mx.edu.chapingo.siani.repository;

import mx.edu.chapingo.siani.domain.ConfirmacionParticipacion;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface ConfirmacionParticipacionRepository extends JpaRepository<ConfirmacionParticipacion, Long> {
    Optional<ConfirmacionParticipacion> findByAlumnoId(Long alumnoId);
}
