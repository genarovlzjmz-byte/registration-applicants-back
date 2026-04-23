-- Crear la secuencia para generar folios de alumnos
CREATE SEQUENCE IF NOT EXISTS siani.seq_folio_alumno
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

-- Eliminar trigger existente si existe
DROP TRIGGER IF EXISTS trg_generar_folio ON siani.alumnos;

-- Eliminar función existente si existe
DROP FUNCTION IF EXISTS siani.generar_folio_alumno();

-- Crear la función trigger para generar el folio
CREATE OR REPLACE FUNCTION siani.generar_folio_alumno()
RETURNS TRIGGER AS $$
DECLARE
    v_año TEXT;
    v_secuencia INT;
BEGIN
    -- Obtener el año actual
    v_año := EXTRACT(YEAR FROM CURRENT_DATE)::TEXT;

    -- Obtener el siguiente valor de la secuencia
    v_secuencia := nextval('siani.seq_folio_alumno');

    -- Generar el folio con formato: AÑO-NÚMERO (ej: 2026-00001)
    NEW.folio := v_año || '-' || LPAD(v_secuencia::TEXT, 5, '0');

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Crear el trigger que se ejecuta antes de insertar
CREATE TRIGGER trg_generar_folio
    BEFORE INSERT ON siani.alumnos
    FOR EACH ROW
    WHEN (NEW.folio IS NULL)
    EXECUTE FUNCTION siani.generar_folio_alumno();

-- Verificar que la secuencia se creó correctamente
SELECT sequence_name FROM information_schema.sequences WHERE sequence_schema = 'siani';

