import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class CSVRecorder {
    private static CSVRecorder instance;
    private BufferedWriter writer;
    private boolean headerWritten = false;

    private CSVRecorder(String filename) throws IOException {
        writer = new BufferedWriter(new FileWriter(filename, true));
    }

    public static synchronized void init(String filename) throws IOException {
        if (instance == null) {
            instance = new CSVRecorder(filename);
        }
    }

    public static synchronized void log(
            String escenario,
            String modoCifrado,      // "SIMÉTRICO" o "ASIMÉTRICO"
            int delegadoId,
            long tiempoFirmaNs,
            long tiempoCifradoNs,
            long tiempoVerificacionNs,
            long tiempoTotalMs
    ) throws IOException {
        if (instance == null) {
            throw new IllegalStateException("CSVRecorder no inicializado. Llame a init() primero.");
        }
        if (!instance.headerWritten) {
            instance.writer.write("Timestamp,Escenario,Modo,DelegadoID,Firma_ns,Cifrado_ns,Verificacion_ns,Total_ms");
            instance.writer.newLine();
            instance.headerWritten = true;
        }
        String timestamp = LocalDateTime.now()
                .format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        String row = String.join(",",
                timestamp,
                escenario,
                modoCifrado,
                String.valueOf(delegadoId),
                String.valueOf(tiempoFirmaNs),
                String.valueOf(tiempoCifradoNs),
                String.valueOf(tiempoVerificacionNs),
                String.valueOf(tiempoTotalMs)
        );
        instance.writer.write(row);
        instance.writer.newLine();
        instance.writer.flush();
    }

    public static synchronized void close() throws IOException {
        if (instance != null) {
            instance.writer.close();
            instance = null;
        }
    }
}
