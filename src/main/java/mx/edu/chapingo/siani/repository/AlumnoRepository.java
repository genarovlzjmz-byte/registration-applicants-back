package mx.edu.chapingo.siani.repository;

import mx.edu.chapingo.siani.domain.Alumno;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;

public interface AlumnoRepository extends JpaRepository<Alumno, Long> {
    Optional<Alumno> findByCurp(String curp);
    Optional<Alumno> findByFolio(String folio);
    boolean existsByCurp(String curp);
    boolean existsByEmail(String email);
    Optional<Alumno> findByUsuarioId(Long usuarioId);
    List<Alumno> findAllByOrderByFechaRegistroDesc();
}
