package mx.edu.chapingo.siani.repository;

import mx.edu.chapingo.siani.domain.ContactoEmergencia;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface ContactoEmergenciaRepository extends JpaRepository<ContactoEmergencia, Long> {
    Optional<ContactoEmergencia> findByAlumnoId(Long alumnoId);
}
