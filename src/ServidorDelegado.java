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
    private String escenario;
    private String modo;

    public ServidorDelegado(
            Socket socket,
            TablaServicios tabla,
            GestorLlaves gestor,
            String escenario,
            String modo
    ) {
        this.socket     = socket;
        this.tabla      = tabla;
        this.gestor     = gestor;
        this.escenario  = escenario;
        this.modo       = modo;
    }

    @Override
    public void run() {
        long tStartTotal = System.currentTimeMillis();
        long tiempoFirma = 0, tiempoCifrado = 0, tiempoVerificacion = 0;

        try (
                DataInputStream dis  = new DataInputStream(socket.getInputStream());
                DataOutputStream dos = new DataOutputStream(socket.getOutputStream())
        ) {
            String saludo = dis.readUTF();
            if (!"HELLO".equals(saludo)) return;

            byte[] reto = new byte[32];
            new SecureRandom().nextBytes(reto);
            FirmaDigital firmaR = new FirmaDigital(gestor.getPrivateKey(), gestor.getPublicKey());
            final byte[] retoF = reto;
            tiempoFirma = MedidorTiempos.medirFirma(() -> {
                try { firmaR.sign(retoF); } catch(Exception ignored){}
            });
            byte[] retoFirmado = firmaR.sign(reto);

            dos.writeInt(reto.length);
            dos.write(reto);
            dos.writeInt(retoFirmado.length);
            dos.write(retoFirmado);
            dos.flush();

            String resp = dis.readUTF();
            if (!"OK".equals(resp)) return;

            UtilidadesProtocolo.SessionKeys sk = UtilidadesProtocolo.performKeyExchangeAsServer(socket);
            byte[] tablaBytes = tabla.serializar();
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            Cipher cif = Cipher.getInstance("AES/CBC/PKCS5Padding");

            final byte[] tb = tablaBytes;
            final IvParameterSpec ivs = new IvParameterSpec(iv);
            final Cipher cf = cif;
            final javax.crypto.SecretKey keyEnc = sk.getEncryptionKey();
            tiempoCifrado = MedidorTiempos.medirCifrado(() -> {
                try {
                    cf.init(Cipher.ENCRYPT_MODE, keyEnc, ivs);
                    cf.doFinal(tb);
                } catch(Exception ignored){}
            });

            cif.init(Cipher.ENCRYPT_MODE, keyEnc, new IvParameterSpec(iv));
            byte[] ct = cif.doFinal(tablaBytes);
            byte[] hmac = UtilidadesProtocolo.hmac(sk.getHmacKey(), tablaBytes);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            DataOutputStream pdos = new DataOutputStream(bos);
            pdos.writeInt(iv.length); pdos.write(iv);
            pdos.writeInt(ct.length); pdos.write(ct);
            pdos.writeInt(hmac.length); pdos.write(hmac);
            pdos.flush();
            UtilidadesProtocolo.sendBytes(socket, bos.toByteArray());

            byte[] req = UtilidadesProtocolo.receiveBytes(socket);
            tiempoVerificacion = MedidorTiempos.medirVerificacion(() -> {
                try { UtilidadesProtocolo.decryptAndVerify(req, sk); }
                catch(Exception ignored){}
            });

            int id = Integer.parseInt(new String(UtilidadesProtocolo.decryptAndVerify(req, sk)));
            TablaServicios.Servicio s = tabla.getServicio(id);
            String out = s != null ? s.getIp()+","+s.getPuerto() : "-1,-1";
            UtilidadesProtocolo.sendBytes(socket, UtilidadesProtocolo.encryptAndHmac(out.getBytes(), sk));

        } catch (Exception e) {
        } finally {
            long tEndTotal = System.currentTimeMillis();
            long totalMs = tEndTotal - tStartTotal;
            try {
                CSVRecorder.log(
                        escenario,
                        modo,
                        socket.getPort(),
                        tiempoFirma,
                        tiempoCifrado,
                        tiempoVerificacion,
                        totalMs
                );
            } catch (IOException ignored) {}
            try { socket.close(); } catch(IOException ignored){}
        }
    }
}
