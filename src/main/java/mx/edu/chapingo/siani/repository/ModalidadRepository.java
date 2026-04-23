package mx.edu.chapingo.siani.repository;

import mx.edu.chapingo.siani.domain.ModalidadIngreso;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;

public interface ModalidadRepository extends JpaRepository<ModalidadIngreso, Long> {
    List<ModalidadIngreso> findByActivoTrueOrderByOrdenAsc();
    Optional<ModalidadIngreso> findByClave(String clave);
}
