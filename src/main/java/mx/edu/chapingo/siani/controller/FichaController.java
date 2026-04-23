package mx.edu.chapingo.siani.controller;

import lombok.RequiredArgsConstructor;
import mx.edu.chapingo.siani.domain.Usuario;
import mx.edu.chapingo.siani.service.FichaService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/aspirante")
@RequiredArgsConstructor
public class FichaController {

    private final FichaService fichaService;

    @GetMapping("/ficha")
    public ResponseEntity<byte[]> descargarFicha(@AuthenticationPrincipal Usuario usuario) {
        byte[] pdfBytes = fichaService.generarFicha(usuario.getId());

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=ficha-examen.pdf")
                .contentType(MediaType.APPLICATION_PDF)
                .contentLength(pdfBytes.length)
                .body(pdfBytes);
    }
}
