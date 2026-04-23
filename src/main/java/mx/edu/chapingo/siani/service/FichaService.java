package mx.edu.chapingo.siani.service;

import com.lowagie.text.*;
import com.lowagie.text.Font;
import com.lowagie.text.pdf.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import mx.edu.chapingo.siani.domain.*;
import mx.edu.chapingo.siani.exception.BusinessException;
import mx.edu.chapingo.siani.repository.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.time.format.DateTimeFormatter;

@Service
@RequiredArgsConstructor
@Slf4j
public class FichaService {

    private final AlumnoRepository alumnoRepo;
    private final DatosPersonalesRepository datosPersonalesRepo;
    private final ConfirmacionParticipacionRepository confirmacionRepo;
    private final SedeExamenRepository sedeRepo;

    // Fuentes
    private static final Font TITLE_FONT = new Font(Font.HELVETICA, 16, Font.BOLD, new Color(21, 101, 192));
    private static final Font SUBTITLE_FONT = new Font(Font.HELVETICA, 12, Font.BOLD);
    private static final Font LABEL_FONT = new Font(Font.HELVETICA, 9, Font.BOLD, Color.DARK_GRAY);
    private static final Font VALUE_FONT = new Font(Font.HELVETICA, 10, Font.NORMAL);
    private static final Font SMALL_FONT = new Font(Font.HELVETICA, 8, Font.NORMAL, Color.GRAY);
    private static final Font ALERT_FONT = new Font(Font.HELVETICA, 10, Font.BOLD, new Color(183, 28, 28));

    @Transactional(readOnly = true)
    public byte[] generarFicha(Long usuarioId) {
        Alumno alumno = alumnoRepo.findByUsuarioId(usuarioId)
                .orElseThrow(() -> new BusinessException("Alumno no encontrado"));

        ConfirmacionParticipacion conf = confirmacionRepo.findByAlumnoId(alumno.getId())
                .orElseThrow(() -> new BusinessException("Debes confirmar tu participación antes de generar la ficha"));

        if (!Boolean.TRUE.equals(conf.getCompletado())) {
            throw new BusinessException("Completa todas las secciones antes de generar la ficha");
        }

        DatosPersonalesAspirante dp = datosPersonalesRepo.findByAlumnoId(alumno.getId()).orElse(null);

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            Document document = new Document(PageSize.LETTER, 40, 40, 30, 30);
            PdfWriter writer = PdfWriter.getInstance(document, baos);
            document.open();

            // === ENCABEZADO ===
            Paragraph header = new Paragraph();
            header.setAlignment(Element.ALIGN_CENTER);
            header.add(new Chunk("UNIVERSIDAD AUTÓNOMA CHAPINGO\n", TITLE_FONT));
            header.add(new Chunk("Sistema Integral de Administración de Nuevo Ingreso\n", SUBTITLE_FONT));
            header.add(new Chunk("FICHA DE EXAMEN DE ADMISIÓN\n\n", SUBTITLE_FONT));
            document.add(header);

            // === DATOS DEL ASPIRANTE ===
            PdfPTable datosTable = new PdfPTable(4);
            datosTable.setWidthPercentage(100);
            datosTable.setWidths(new float[]{1.2f, 2f, 1.2f, 2f});

            addLabelValue(datosTable, "FOLIO:", alumno.getFolio());
            addLabelValue(datosTable, "CURP:", alumno.getCurp());
            addLabelValue(datosTable, "NOMBRE:", alumno.getNombre());
            addLabelValue(datosTable, "AP. PATERNO:", alumno.getApellidoPaterno());
            addLabelValue(datosTable, "AP. MATERNO:", alumno.getApellidoMaterno());
            addLabelValue(datosTable, "EMAIL:", alumno.getEmail());

            if (dp != null) {
                addLabelValue(datosTable, "SEXO:", dp.getSexo() != null ? (dp.getSexo().equals("M") ? "Masculino" : "Femenino") : "");
                addLabelValue(datosTable, "CELULAR:", dp.getTelefonoCelular() != null ? dp.getTelefonoCelular() : "");
                if (dp.getFechaNacimiento() != null) {
                    addLabelValue(datosTable, "F. NACIMIENTO:", dp.getFechaNacimiento().format(DateTimeFormatter.ofPattern("dd/MM/yyyy")));
                } else {
                    addLabelValue(datosTable, "F. NACIMIENTO:", "");
                }
            }

            document.add(datosTable);
            document.add(new Paragraph("\n"));

            // === DATOS DE LA SEDE ===
            PdfPTable sedeTable = new PdfPTable(2);
            sedeTable.setWidthPercentage(100);
            sedeTable.setWidths(new float[]{1.5f, 3f});

            PdfPCell sedeHeader = new PdfPCell(new Phrase("SEDE DE EXAMEN", SUBTITLE_FONT));
            sedeHeader.setColspan(2);
            sedeHeader.setBackgroundColor(new Color(232, 245, 233));
            sedeHeader.setPadding(8);
            sedeHeader.setHorizontalAlignment(Element.ALIGN_CENTER);
            sedeTable.addCell(sedeHeader);

            if (conf.getSedeId() != null) {
                SedeExamen sede = sedeRepo.findById(conf.getSedeId()).orElse(null);
                if (sede != null) {
                    addLabelValueRow(sedeTable, "Sede:", sede.getNombre());
                    addLabelValueRow(sedeTable, "Escuela:", sede.getEscuela() != null ? sede.getEscuela() : "");
                    addLabelValueRow(sedeTable, "Dirección:", sede.getDireccion() != null ? sede.getDireccion() : "");
                }
            }

            if (conf.getFechaConfirmacion() != null) {
                addLabelValueRow(sedeTable, "Confirmación:",
                        conf.getFechaConfirmacion().format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm")));
            }

            document.add(sedeTable);
            document.add(new Paragraph("\n"));

            // === ESPACIO PARA FOTOGRAFÍA ===
            PdfPTable fotoTable = new PdfPTable(2);
            fotoTable.setWidthPercentage(100);
            fotoTable.setWidths(new float[]{3f, 1f});

            // Instrucciones
            PdfPCell instrCell = new PdfPCell();
            instrCell.setBorderWidth(0);
            instrCell.addElement(new Paragraph("INSTRUCCIONES:", SUBTITLE_FONT));
            instrCell.addElement(new Paragraph("• Coloca fotografía tamaño infantil (2.5 x 3 cm)", VALUE_FONT));
            instrCell.addElement(new Paragraph("• Blanco/negro o color, reciente", VALUE_FONT));
            instrCell.addElement(new Paragraph("• Firma con tinta azul sobre la fotografía", VALUE_FONT));
            instrCell.addElement(new Paragraph("• Presenta esta ficha con identificación oficial", VALUE_FONT));
            instrCell.addElement(new Paragraph("\n"));
            instrCell.addElement(new Paragraph("IDENTIFICACIONES VÁLIDAS:", LABEL_FONT));
            instrCell.addElement(new Paragraph("1. Credencial escolar con foto", SMALL_FONT));
            instrCell.addElement(new Paragraph("2. Constancia de estudios con foto", SMALL_FONT));
            instrCell.addElement(new Paragraph("3. INE / Pasaporte / Visa", SMALL_FONT));
            instrCell.addElement(new Paragraph("4. Licencia de manejo", SMALL_FONT));
            fotoTable.addCell(instrCell);

            // Recuadro de foto
            PdfPCell fotoCell = new PdfPCell();
            fotoCell.setFixedHeight(100);
            fotoCell.setBorderWidth(2);
            fotoCell.setBorderColor(Color.DARK_GRAY);
            fotoCell.setHorizontalAlignment(Element.ALIGN_CENTER);
            fotoCell.setVerticalAlignment(Element.ALIGN_MIDDLE);
            Paragraph fotoText = new Paragraph("FOTOGRAFÍA\n2.5 x 3 cm\n(firmar con\ntinta azul)", SMALL_FONT);
            fotoText.setAlignment(Element.ALIGN_CENTER);
            fotoCell.addElement(fotoText);
            fotoTable.addCell(fotoCell);

            document.add(fotoTable);
            document.add(new Paragraph("\n"));

            // === ADVERTENCIA ===
            Paragraph advertencia = new Paragraph();
            advertencia.setAlignment(Element.ALIGN_CENTER);
            advertencia.add(new Chunk("SIN FICHA NI IDENTIFICACIÓN NO PODRÁS PRESENTAR EL EXAMEN", ALERT_FONT));
            document.add(advertencia);

            document.add(new Paragraph("\n"));

            // === PIE ===
            Paragraph pie = new Paragraph();
            pie.setAlignment(Element.ALIGN_CENTER);
            pie.add(new Chunk("\"Esfuerzo, perseverancia y determinación, te llevarán a Chapingo. ¡Mucho éxito!\"",
                    new Font(Font.HELVETICA, 10, Font.BOLDITALIC, new Color(21, 101, 192))));
            document.add(pie);

            document.close();
            log.info("Ficha PDF generada para alumno {}", alumno.getFolio());
            return baos.toByteArray();

        } catch (DocumentException e) {
            throw new BusinessException("Error al generar la ficha PDF: " + e.getMessage());
        }
    }

    private void addLabelValue(PdfPTable table, String label, String value) {
        PdfPCell labelCell = new PdfPCell(new Phrase(label, LABEL_FONT));
        labelCell.setBorderWidth(0.5f);
        labelCell.setPadding(5);
        labelCell.setBackgroundColor(new Color(245, 245, 245));
        table.addCell(labelCell);

        PdfPCell valueCell = new PdfPCell(new Phrase(value != null ? value : "", VALUE_FONT));
        valueCell.setBorderWidth(0.5f);
        valueCell.setPadding(5);
        table.addCell(valueCell);
    }

    private void addLabelValueRow(PdfPTable table, String label, String value) {
        PdfPCell labelCell = new PdfPCell(new Phrase(label, LABEL_FONT));
        labelCell.setPadding(5);
        labelCell.setBackgroundColor(new Color(245, 245, 245));
        table.addCell(labelCell);

        PdfPCell valueCell = new PdfPCell(new Phrase(value != null ? value : "", VALUE_FONT));
        valueCell.setPadding(5);
        table.addCell(valueCell);
    }
}
