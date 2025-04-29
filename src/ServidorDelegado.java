import java.net.Socket;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
        try (
                DataInputStream dis = new DataInputStream(socket.getInputStream());
                DataOutputStream dos = new DataOutputStream(socket.getOutputStream())
        ) {
            String saludo = dis.readUTF();
            if (!"HELLO".equals(saludo)) {
                socket.close();
                return;
            }
            byte[] reto = new byte[32];
            new SecureRandom().nextBytes(reto);
            FirmaDigital firmaR = new FirmaDigital(gestor.getPrivateKey(), gestor.getPublicKey());
            byte[] retoFirmado = firmaR.sign(reto);
            dos.writeInt(reto.length);
            dos.write(reto);
            dos.writeInt(retoFirmado.length);
            dos.write(retoFirmado);
            dos.flush();
            String respuesta = dis.readUTF();
            if (!"OK".equals(respuesta)) {
                socket.close();
                return;
            }
            UtilidadesProtocolo.SessionKeys sk = UtilidadesProtocolo.performKeyExchangeAsServer(socket);
            byte[] tablaBytes = tabla.serializar();
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            Cipher cifrador = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cifrador.init(Cipher.ENCRYPT_MODE, sk.getEncryptionKey(), new IvParameterSpec(iv));
            byte[] ct = cifrador.doFinal(tablaBytes);
            byte[] hmac = UtilidadesProtocolo.hmac(sk.getHmacKey(), tablaBytes);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            DataOutputStream pdos = new DataOutputStream(bos);
            pdos.writeInt(iv.length);
            pdos.write(iv);
            pdos.writeInt(ct.length);
            pdos.write(ct);
            pdos.writeInt(hmac.length);
            pdos.write(hmac);
            pdos.flush();
            UtilidadesProtocolo.sendBytes(socket, bos.toByteArray());
            byte[] reqPayload = UtilidadesProtocolo.receiveBytes(socket);
            byte[] plain = UtilidadesProtocolo.decryptAndVerify(reqPayload, sk);
            int id = Integer.parseInt(new String(plain));
            TablaServicios.Servicio serv = tabla.getServicio(id);
            String resp = serv != null ? serv.getIp() + "," + serv.getPuerto() : "-1,-1";
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
