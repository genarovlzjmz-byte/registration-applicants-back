package mx.edu.chapingo.siani.repository;

import mx.edu.chapingo.siani.domain.CodigoPostal;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface CodigoPostalRepository extends JpaRepository<CodigoPostal, Long> {
    List<CodigoPostal> findByMunicipioIdAndActivoTrue(Long municipioId);

    // Para autocompletado: buscar CPs que empiecen con el código ingresado
    @Query("SELECT cp FROM CodigoPostal cp " +
           "JOIN FETCH cp.municipio m " +
           "JOIN FETCH m.estado e " +
           "WHERE cp.codigo LIKE :codigo% AND cp.activo = true " +
           "ORDER BY cp.codigo ASC")
    List<CodigoPostal> buscarPorCodigoStartingWith(@Param("codigo") String codigo);

    // Buscar código postal exacto con municipio y estado
    @Query("SELECT cp FROM CodigoPostal cp " +
           "JOIN FETCH cp.municipio m " +
           "JOIN FETCH m.estado e " +
           "WHERE cp.codigo = :codigo AND cp.activo = true")
    Optional<CodigoPostal> findByCodigoWithMunicipioAndEstado(@Param("codigo") String codigo);
}

