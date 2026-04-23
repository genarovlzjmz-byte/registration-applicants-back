package mx.edu.chapingo.siani.dto.response;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginStep1Response {
    private Long usuarioId;
    private String email;
    private String nombre;
    private String mensaje;

    public LoginStep1Response(Long usuarioId, String email, String nombre) {
        this.usuarioId = usuarioId;
        this.email = email;
        this.nombre = nombre;
        this.mensaje = "Se envió un código de verificación a " + maskEmail(email);
    }

    /**
     * Enmascara el email para no exponer el completo en la respuesta.
     * Ej: g****z@gmail.com
     */
    private String maskEmail(String email) {
        int at = email.indexOf('@');
        if (at <= 2) return email;
        return email.charAt(0)
                + "****"
                + email.substring(at - 1);
    }
}

