package mx.edu.chapingo.siani.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import mx.edu.chapingo.siani.dto.request.LoginRequest;
import mx.edu.chapingo.siani.dto.response.ApiResponse;
import mx.edu.chapingo.siani.dto.response.TokenResponse;
import mx.edu.chapingo.siani.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Tag(name = "Autenticación", description = "Login con CURP, email y password")
public class AuthController {

    private final AuthService authService;

    @Operation(
            summary = "Login",
            description = "Valida email + CURP + password. Si es correcto, retorna el token JWT."
    )
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<TokenResponse>> login(
            @Valid @RequestBody LoginRequest request) {

        TokenResponse token = authService.login(request);

        return ResponseEntity.ok(ApiResponse.ok("Login exitoso", token));
    }
}
