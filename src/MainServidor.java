import java.net.ServerSocket;
import java.net.Socket;

public class MainServidor {
    public static void main(String[] args) throws Exception {
        int port = 5000;
        String publicKeyPath = "llave_publica.der";
        String privateKeyPath = "llave_privada.der";
        if (args.length == 3) {
            port = Integer.parseInt(args[0]);
            publicKeyPath = args[1];
            privateKeyPath = args[2];
        }
        GestorLlaves gestor = new GestorLlaves(publicKeyPath, privateKeyPath);
        TablaServicios tabla = new TablaServicios();
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            while (true) {
                Socket client = serverSocket.accept();
                new Thread(new ServidorDelegado(client, tabla, gestor)).start();
            }
        }
    }
}
