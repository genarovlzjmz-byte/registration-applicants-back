package mx.edu.chapingo.siani.repository;

import mx.edu.chapingo.siani.domain.EscuelaProcedencia;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface EscuelaProcedenciaRepository extends JpaRepository<EscuelaProcedencia, Long> {
    Optional<EscuelaProcedencia> findByAlumnoId(Long alumnoId);
}
