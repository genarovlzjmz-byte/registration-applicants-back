package mx.edu.chapingo.siani.repository;

import mx.edu.chapingo.siani.domain.SedeExamen;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface SedeExamenRepository extends JpaRepository<SedeExamen, Long> {
    List<SedeExamen> findByEstadoIdAndActivoTrue(Long estadoId);
}
