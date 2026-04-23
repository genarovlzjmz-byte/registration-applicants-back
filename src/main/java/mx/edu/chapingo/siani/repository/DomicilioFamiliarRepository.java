package mx.edu.chapingo.siani.repository;

import mx.edu.chapingo.siani.domain.DomicilioFamiliar;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface DomicilioFamiliarRepository extends JpaRepository<DomicilioFamiliar, Long> {
    Optional<DomicilioFamiliar> findByAlumnoId(Long alumnoId);
}
