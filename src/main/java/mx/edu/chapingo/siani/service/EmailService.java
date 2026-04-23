package mx.edu.chapingo.siani.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import jakarta.mail.internet.MimeMessage;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username:noreply@quimios.com}")
    private String fromEmail;

    @Value("${quimios.app.name:QUIMIOS}")
    private String appName;

    /**
     * Envía el código de verificación por email.
     * Se ejecuta async para no bloquear el flujo de login.
     */
    @Async
    public void enviarCodigoVerificacion(String destinatario, String codigo, int minutosExpiracion) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(destinatario);
            helper.setSubject("Código de verificación - " + appName);

            String html = """
                <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px;">
                    <div style="text-align: center; margin-bottom: 24px;">
                        <h2 style="color: #1e5f94; margin: 0;">%s</h2>
                        <p style="color: #666; font-size: 14px;">Código de verificación de seguridad</p>
                    </div>
                    
                    <div style="background: #f8f9fa; border-radius: 12px; padding: 24px; text-align: center; margin-bottom: 24px;">
                        <p style="color: #666; font-size: 14px; margin: 0 0 12px;">Tu código de verificación es:</p>
                        <div style="font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #1e5f94; font-family: monospace;">
                            %s
                        </div>
                    </div>
                    
                    <div style="font-size: 13px; color: #888; text-align: center;">
                        <p>Este código expira en <strong>%d minutos</strong>.</p>
                        <p>Si no solicitaste este código, ignora este mensaje.</p>
                        <p style="margin-top: 16px; color: #aaa;">No compartas este código con nadie.</p>
                    </div>
                </div>
                """.formatted(appName, codigo, minutosExpiracion);

            helper.setText(html, true);
            mailSender.send(message);

            log.info("Código de verificación enviado a: {}", destinatario);

        } catch (Exception e) {
            log.error("Error enviando email a {}: {}", destinatario, e.getMessage());
            // No lanzar excepción — el código ya está en BD
            // El usuario puede solicitar reenvío
        }
    }

    /**
     * Reenviar código (mismo contenido, solo envía de nuevo).
     */
    @Async
    public void reenviarCodigo(String destinatario, String codigo, int minutosExpiracion) {
        enviarCodigoVerificacion(destinatario, codigo, minutosExpiracion);
    }
}
