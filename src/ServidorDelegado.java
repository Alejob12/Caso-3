import java.net.Socket;
import java.io.*;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

public class ServidorDelegado implements Runnable {

    private Socket socket;
    private TablaServicios tabla;
    private GestorLlaves gestor;

    public ServidorDelegado(Socket socket, TablaServicios tabla, GestorLlaves gestor) {
        this.socket = socket;
        this.tabla = tabla;
        this.gestor = gestor;
    }

    @Override
    public void run() {
        try {
            UtilidadesProtocolo.SessionKeys sk =
                    UtilidadesProtocolo.performKeyExchangeAsServer(socket);

            byte[] tablaBytes = tabla.serializar();

            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            Cipher cifrador = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cifrador.init(Cipher.ENCRYPT_MODE, sk.getEncryptionKey(), new IvParameterSpec(iv));
            byte[] ct = cifrador.doFinal(tablaBytes);

            FirmaDigital firma =
                    new FirmaDigital(gestor.getPrivateKey(), gestor.getPublicKey());
            byte[] signature = firma.sign(ct);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(bos);
            dos.writeInt(iv.length);
            dos.write(iv);
            dos.writeInt(ct.length);
            dos.write(ct);
            dos.writeInt(signature.length);
            dos.write(signature);
            dos.flush();

            UtilidadesProtocolo.sendBytes(socket, bos.toByteArray());

            byte[] reqPayload = UtilidadesProtocolo.receiveBytes(socket);
            byte[] plain = UtilidadesProtocolo.decryptAndVerify(reqPayload, sk);

            int id = Integer.parseInt(new String(plain));
            TablaServicios.Servicio serv = tabla.getServicio(id);
            String resp = serv != null
                    ? serv.getIp() + "," + serv.getPuerto()
                    : "-1,-1";

            byte[] respPayload = UtilidadesProtocolo.encryptAndHmac(resp.getBytes(), sk);
            UtilidadesProtocolo.sendBytes(socket, respPayload);

        } catch (Exception e) {
            System.err.println("Error en la consulta");
        } finally {
            try {
                socket.close();
            } catch (IOException ignored) {}
        }
    }
}
