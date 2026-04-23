package mx.edu.chapingo.siani.service;

import lombok.RequiredArgsConstructor;
import mx.edu.chapingo.siani.domain.Usuario;
import mx.edu.chapingo.siani.dto.request.LoginRequest;
import mx.edu.chapingo.siani.dto.response.TokenResponse;
import mx.edu.chapingo.siani.exception.BusinessException;
import mx.edu.chapingo.siani.exception.DuplicateResourceException;
import mx.edu.chapingo.siani.repository.UsuarioRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UsuarioRepository usuarioRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    /**
     * Login directo — valida credenciales (email + CURP + password) y retorna JWT.
     */
    @Transactional(readOnly = true)
    public TokenResponse login(LoginRequest request) {
        // Verificar que CURP y email correspondan al mismo usuario
        Usuario usuario = usuarioRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new BusinessException("Credenciales inválidas"));

        if (!usuario.getCurp().equalsIgnoreCase(request.getCurp())) {
            throw new BusinessException("La CURP no corresponde al correo proporcionado");
        }

        if (!usuario.getActivo()) {
            throw new BusinessException(
                "CANCELASTE TU PARTICIPACIÓN EN EL EXAMEN DE ADMISIÓN 2026 DE LA UACh.");
        }

        // Spring Security valida el password
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        // Credenciales válidas — generar JWT
        String token = jwtService.generateToken(usuario);

        return TokenResponse.builder()
                .token(token)
                .tipo("Bearer")
                .expiresIn(jwtService.getExpirationMs())
                .email(usuario.getEmail())
                .curp(usuario.getCurp())
                .nombre(usuario.getEmail())
                .rol(usuario.getRol())
                .build();
    }

    /**
     * Crear cuenta de acceso (usuario).
     * Paso previo al registro completo del alumno.
     */
    @Transactional
    public Usuario crearUsuario(String curp, String email, String password,
                                 String passwordConfirmacion) {
        // Validar que passwords coincidan
        if (!password.equals(passwordConfirmacion)) {
            throw new BusinessException("Las contraseñas no coinciden");
        }

        // Validar duplicados
        if (usuarioRepository.existsByCurp(curp.toUpperCase())) {
            throw new DuplicateResourceException("Usuario", "CURP", curp);
        }
        if (usuarioRepository.existsByEmail(email.toLowerCase())) {
            throw new DuplicateResourceException("Usuario", "email", email);
        }

        Usuario usuario = Usuario.builder()
                .curp(curp.toUpperCase())
                .email(email.toLowerCase())
                .passwordHash(passwordEncoder.encode(password))
                .rol("ASPIRANTE")
                .activo(true)
                .emailVerificado(false)
                .build();

        return usuarioRepository.save(usuario);
    }
}
