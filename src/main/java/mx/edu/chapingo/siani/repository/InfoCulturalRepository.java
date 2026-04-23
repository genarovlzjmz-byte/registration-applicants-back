package mx.edu.chapingo.siani.repository;

import mx.edu.chapingo.siani.domain.InfoCultural;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface InfoCulturalRepository extends JpaRepository<InfoCultural, Long> {
    Optional<InfoCultural> findByAlumnoId(Long alumnoId);
}
