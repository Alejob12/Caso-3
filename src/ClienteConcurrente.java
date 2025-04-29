import java.util.Scanner;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

public class ClienteConcurrente implements Runnable {
    private static final AtomicInteger clienteCompletados = new AtomicInteger(0);
    private static CountDownLatch latch;
    private final int clienteId;
    private final String host;
    private final int port;
    private final String publicKeyPath;

    public ClienteConcurrente(int clienteId, String host, int port, String publicKeyPath) {
        this.clienteId = clienteId;
        this.host = host;
        this.port = port;
        this.publicKeyPath = publicKeyPath;
    }

    @Override
    public void run() {
        try {
            System.out.println("[ClienteConcurrente #" + clienteId + "] Iniciando cliente");
            Cliente.main(new String[] {host, String.valueOf(port), publicKeyPath});

            System.out.println("[ClienteConcurrente #" + clienteId + "] Cliente completado");

            int completados = clienteCompletados.incrementAndGet();
            System.out.println("[ClienteConcurrente] Clientes completados: " + completados);

            latch.countDown();
        } catch (Exception e) {
            System.err.println("[ClienteConcurrente #" + clienteId + "] Error: " + e.getMessage());
            e.printStackTrace();
            latch.countDown();
        }
    }

    public static void main(String[] args) {
        String host = args.length > 0 ? args[0] : "localhost";
        int port = args.length > 1 ? Integer.parseInt(args[1]) : 5000;
        String publicKeyPath = args.length > 2 ? args[2] : "llave_publica.der";

        Scanner scanner = new Scanner(System.in);
        System.out.println("Seleccione el número de clientes concurrentes (4, 16, 32 o 64): ");
        int numeroDeClientes = 64; // Valor por defecto

        try {
            numeroDeClientes = scanner.nextInt();

            if (numeroDeClientes != 4 && numeroDeClientes != 16 && numeroDeClientes != 32 && numeroDeClientes != 64) {
                System.out.println("Número de clientes ajustado a un valor válido (debe ser 4, 16, 32 o 64)");
                if (numeroDeClientes < 10) numeroDeClientes = 4;
                else if (numeroDeClientes < 24) numeroDeClientes = 16;
                else if (numeroDeClientes < 48) numeroDeClientes = 32;
                else numeroDeClientes = 64;
            }
        } catch (Exception e) {
            System.out.println("Entrada inválida. Usando el valor por defecto (64 clientes).");
        }

        System.out.println("Iniciando prueba con " + numeroDeClientes + " clientes concurrentes");

        latch = new CountDownLatch(numeroDeClientes);
        clienteCompletados.set(0);

        long tiempoInicio = System.currentTimeMillis();

        for (int i = 0; i < numeroDeClientes; i++) {
            new Thread(new ClienteConcurrente(i+1, host, port, publicKeyPath)).start();
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        try {
            System.out.println("Esperando a que todos los clientes terminen...");
            latch.await();

            long tiempoFin = System.currentTimeMillis();
            long tiempoTotal = tiempoFin - tiempoInicio;

            System.out.println("\n==== RESULTADOS DE LA PRUEBA CONCURRENTE ====");
            System.out.println("Número de clientes: " + numeroDeClientes);
            System.out.println("Tiempo total de ejecución: " + tiempoTotal + " ms");
            System.out.println("Tiempo promedio por cliente: " + (tiempoTotal / numeroDeClientes) + " ms");
            System.out.println("Clientes completados: " + clienteCompletados.get());
            System.out.println("==========================================");

        } catch (InterruptedException e) {
            System.err.println("La espera fue interrumpida: " + e.getMessage());
            e.printStackTrace();
        }
    }
}