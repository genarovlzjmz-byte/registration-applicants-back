package mx.edu.chapingo.siani.repository;

import mx.edu.chapingo.siani.domain.Colonia;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ColoniaRepository extends JpaRepository<Colonia, Long> {
    List<Colonia> findByCodigoPostalIdAndActivoTrueOrderByNombreAsc(Long codigoPostalId);
    List<Colonia> findByCodigoPostalCodigoAndActivoTrueOrderByNombreAsc(String codigoPostal);
}

