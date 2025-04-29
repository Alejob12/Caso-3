import java.net.Socket;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.util.Map;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

public class Cliente {

    public static void main(String[] args) throws Exception {
        String host = args.length > 0 ? args[0] : "localhost";
        int port = args.length > 1 ? Integer.parseInt(args[1]) : 5000;
        String publicKeyPath = args.length > 2 ? args[2] : "llave_publica.der";

        GestorLlaves gestor = new GestorLlaves(null, publicKeyPath);
        PublicKey serverPub = gestor.getPublicKey();
        FirmaDigital firma = new FirmaDigital(null, serverPub);

        try (Socket socket = new Socket(host, port);
             DataInputStream dis = new DataInputStream(socket.getInputStream());
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream())) {

            socket.setSoTimeout(10000);

            System.out.println("[Cliente] Conectado a " + host + ":" + port);
            dos.writeUTF("HELLO");
            dos.flush();

            int retoLen = dis.readInt();
            byte[] reto = new byte[retoLen];
            dis.readFully(reto);

            int sigLen = dis.readInt();
            byte[] firmaReto = new byte[sigLen];
            dis.readFully(firmaReto);

            final byte[] retoFinal = reto;
            final byte[] firmaRetoFinal = firmaReto;
            long tiempoVerificacion = MedidorTiempos.medirVerificacion(() -> {
                try {
                    firma.verify(retoFinal, firmaRetoFinal);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
            System.out.println("[Cliente] Tiempo de verificación de firma: " + tiempoVerificacion + " ns (" +
                    (tiempoVerificacion / 1_000_000.0) + " ms)");

            boolean ok = firma.verify(reto, firmaReto);
            dos.writeUTF(ok ? "OK" : "ERROR");
            dos.flush();
            if (!ok) return;

            UtilidadesProtocolo.SessionKeys sk = UtilidadesProtocolo.performKeyExchangeAsClient(socket);

            System.out.println("[Cliente] Esperando tabla de servicios");
            byte[] tablePayload = UtilidadesProtocolo.receiveBytes(socket);
            DataInputStream pdip = new DataInputStream(new ByteArrayInputStream(tablePayload));

            int ivLen = pdip.readInt();
            byte[] iv = new byte[ivLen];
            pdip.readFully(iv);

            int ctLen = pdip.readInt();
            byte[] ct = new byte[ctLen];
            pdip.readFully(ct);

            int hmLen = pdip.readInt();
            byte[] hmacRecv = new byte[hmLen];
            pdip.readFully(hmacRecv);

            final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            final IvParameterSpec ivSpec = new IvParameterSpec(iv);
            final byte[] ctFinal = ct;
            final byte[][] tablaBytesHolder = new byte[1][];

            long tiempoDescifrado = MedidorTiempos.medirCifrado(() -> {
                try {
                    cipher.init(Cipher.DECRYPT_MODE, sk.getEncryptionKey(), ivSpec);
                    tablaBytesHolder[0] = cipher.doFinal(ctFinal);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
            System.out.println("[Cliente] Tiempo de descifrado de tabla: " + tiempoDescifrado + " ns (" +
                    (tiempoDescifrado / 1_000_000.0) + " ms)");

            byte[] tablaBytes = tablaBytesHolder[0];

            byte[] hmacCalc = UtilidadesProtocolo.hmac(sk.getHmacKey(), tablaBytes);
            if (!java.security.MessageDigest.isEqual(hmacCalc, hmacRecv)) {
                System.err.println("Error en la consulta");
                return;
            }

            TablaServicios tabla = UtilidadesProtocolo.deserializeTable(tablaBytes);
            System.out.println("Servicios disponibles:");
            tabla.listarServicios().forEach((id, nombre) -> System.out.println(id + ": " + nombre));

            Scanner sc = new Scanner(System.in);
            System.out.print("Seleccione servicio ID: ");
            int idServicio = sc.nextInt();

            byte[] request = UtilidadesProtocolo.encryptAndHmac(
                    String.valueOf(idServicio).getBytes(), sk
            );
            UtilidadesProtocolo.sendBytes(socket, request);

            System.out.println("[Cliente] Esperando respuesta del servidor");
            byte[] response = UtilidadesProtocolo.receiveBytes(socket);
            byte[] plain = UtilidadesProtocolo.decryptAndVerify(response, sk);
            System.out.println("Respuesta: " + new String(plain));
        }
    }
}