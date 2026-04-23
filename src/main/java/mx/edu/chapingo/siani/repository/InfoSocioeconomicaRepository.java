package mx.edu.chapingo.siani.repository;

import mx.edu.chapingo.siani.domain.InfoSocioeconomica;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface InfoSocioeconomicaRepository extends JpaRepository<InfoSocioeconomica, Long> {
    Optional<InfoSocioeconomica> findByAlumnoId(Long alumnoId);
}
