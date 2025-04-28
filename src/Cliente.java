import java.net.Socket;
import java.security.PublicKey;
import java.util.Map;
import java.util.Scanner;

public class Cliente {

    public static void main(String[] args) throws Exception {
        String host          = args.length > 0 ? args[0] : "localhost";
        int port             = args.length > 1 ? Integer.parseInt(args[1]) : 5000;
        String publicKeyPath = args.length > 2 ? args[2] : "llave_publica.der";

        // <-- Aquí pasa primero null (no hay privada) y luego la ruta de la pública:
        GestorLlaves gestor = new GestorLlaves(null, publicKeyPath);
        PublicKey serverPub = gestor.getPublicKey();
        FirmaDigital firma  = new FirmaDigital(null, serverPub);

        try (Socket socket = new Socket(host, port)) {
            UtilidadesProtocolo.SessionKeys sk =
                    UtilidadesProtocolo.performKeyExchangeAsClient(socket);

            byte[] signedEncryptedTable = UtilidadesProtocolo.receiveBytes(socket);
            UtilidadesProtocolo.SignedMessage signedMsg =
                    UtilidadesProtocolo.parseSignedMessage(signedEncryptedTable);

            if (!firma.verify(signedMsg.getCipherText(), signedMsg.getSignature())) {
                System.err.println("Error en la consulta");
                return;
            }

            byte[] tableBytes = UtilidadesProtocolo.decryptAES(
                    signedMsg.getCipherText(), sk.getEncryptionKey(), signedMsg.getIv()
            );
            TablaServicios tabla = UtilidadesProtocolo.deserializeTable(tableBytes);

            System.out.println("Servicios disponibles:");
            tabla.listarServicios()
                    .forEach((id, nombre) -> System.out.println(id + ": " + nombre));

            Scanner sc = new Scanner(System.in);
            int idServicio = sc.nextInt();

            byte[] request = UtilidadesProtocolo.encryptAndHmac(
                    String.valueOf(idServicio).getBytes(), sk
            );
            UtilidadesProtocolo.sendBytes(socket, request);

            byte[] response = UtilidadesProtocolo.receiveBytes(socket);
            byte[] plain = UtilidadesProtocolo.decryptAndVerify(response, sk);
            System.out.println(new String(plain));
        }
    }
}
