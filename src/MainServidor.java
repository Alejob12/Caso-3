import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;
import java.util.concurrent.atomic.AtomicInteger;

public class MainServidor {
    private static final AtomicInteger conexionesActivas = new AtomicInteger(0);
    private static final AtomicInteger totalConexiones = new AtomicInteger(0);
    private static long tiempoInicio;

    public static void main(String[] args) throws Exception {
        // 1. Inicializar CSVRecorder
        CSVRecorder.init("resultados.csv");

        int port = 5000;
        String publicKeyPath  = "llave_publica.der";
        String privateKeyPath = "llave_privada_pkcs8.der";

        if (args.length == 3) {
            port           = Integer.parseInt(args[0]);
            publicKeyPath  = args[1];
            privateKeyPath = args[2];
        }

        Scanner scanner = new Scanner(System.in);
        System.out.print("Ingrese nombre de escenario (e.g. Secuencial32, Concurrente4): ");
        String escenario = scanner.nextLine().trim();

        System.out.print("Modo de cifrado a medir (SIMETRICO o ASIMETRICO): ");
        String modo = scanner.nextLine().trim().toUpperCase();

        System.out.print("¿Desea limitar conexiones concurrentes? (s/n): ");
        String respuesta = scanner.nextLine().trim().toLowerCase();

        int maxConexionesConcurrentes = Integer.MAX_VALUE;
        if (respuesta.equals("s") || respuesta.equals("si") || respuesta.equals("sí")) {
            System.out.print("Número máximo de conexiones concurrentes: ");
            try {
                maxConexionesConcurrentes = Integer.parseInt(scanner.nextLine().trim());
                System.out.println("Límite establecido: " + maxConexionesConcurrentes);
            } catch (NumberFormatException e) {
                System.out.println("Entrada inválida, no se establece límite.");
            }
        }

        GestorLlaves gestor = new GestorLlaves(privateKeyPath, publicKeyPath);
        TablaServicios tabla = new TablaServicios();

        tiempoInicio = System.currentTimeMillis();
        Thread monitor = new Thread(() -> {
            try {
                while (true) {
                    Thread.sleep(5000);
                    mostrarEstadisticas();
                }
            } catch (InterruptedException ignored) {}
        });
        monitor.setDaemon(true);
        monitor.start();

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Servidor escuchando en puerto " + port);

            while (true) {
                Socket client = serverSocket.accept();
                if (conexionesActivas.get() >= maxConexionesConcurrentes) {
                    client.close();
                    continue;
                }
                conexionesActivas.incrementAndGet();
                totalConexiones.incrementAndGet();

                new Thread(new ServidorDelegadoWrapper(
                        client, tabla, gestor, escenario, modo
                )).start();
            }
        } finally {
            CSVRecorder.close();
        }
    }

    private static class ServidorDelegadoWrapper implements Runnable {
        private final Socket clientSocket;
        private final TablaServicios tabla;
        private final GestorLlaves gestor;
        private final String escenario;
        private final String modo;

        public ServidorDelegadoWrapper(
                Socket clientSocket,
                TablaServicios tabla,
                GestorLlaves gestor,
                String escenario,
                String modo
        ) {
            this.clientSocket = clientSocket;
            this.tabla = tabla;
            this.gestor = gestor;
            this.escenario = escenario;
            this.modo = modo;
        }

        @Override
        public void run() {
            try {
                ServidorDelegado delegado = new ServidorDelegado(
                        clientSocket, tabla, gestor, escenario, modo
                );
                delegado.run();
            } finally {
                conexionesActivas.decrementAndGet();
            }
        }
    }

    private static void mostrarEstadisticas() {
        long ahora = System.currentTimeMillis();
        long trans = ahora - tiempoInicio;
        System.out.println("\n=== ESTADÍSTICAS ===");
        System.out.println("Activas: " + conexionesActivas.get());
        System.out.println("Atendidas: " + totalConexiones.get());
        System.out.printf("Conn/s: %.2f%n", totalConexiones.get() / (trans / 1000.0));
        System.out.println("===================\n");
    }
}
