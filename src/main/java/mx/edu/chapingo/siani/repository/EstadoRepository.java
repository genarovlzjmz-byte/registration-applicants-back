package mx.edu.chapingo.siani.repository;

import mx.edu.chapingo.siani.domain.Estado;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;

public interface EstadoRepository extends JpaRepository<Estado, Long> {
    List<Estado> findByActivoTrueOrderByNombreAsc();
    Optional<Estado> findByNombreIgnoreCase(String nombre);
}
