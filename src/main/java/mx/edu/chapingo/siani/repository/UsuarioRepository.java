package mx.edu.chapingo.siani.repository;

import mx.edu.chapingo.siani.domain.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UsuarioRepository extends JpaRepository<Usuario, Long> {
    Optional<Usuario> findByEmail(String email);
    Optional<Usuario> findByCurp(String curp);
    boolean existsByEmail(String email);
    boolean existsByCurp(String curp);
}
