import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;

public class UtilidadesProtocolo {

    public static class SessionKeys {
        private SecretKey encryptionKey;
        private SecretKey hmacKey;
        public SessionKeys(SecretKey encryptionKey, SecretKey hmacKey) {
            this.encryptionKey = encryptionKey;
            this.hmacKey = hmacKey;
        }
        public SecretKey getEncryptionKey() { return encryptionKey; }
        public SecretKey getHmacKey() { return hmacKey; }
    }

    public static class SignedMessage {
        private byte[] iv, cipherText, signature;
        public SignedMessage(byte[] iv, byte[] cipherText, byte[] signature) {
            this.iv = iv; this.cipherText = cipherText; this.signature = signature;
        }
        public byte[] getIv() { return iv; }
        public byte[] getCipherText() { return cipherText; }
        public byte[] getSignature() { return signature; }
    }

    public static SessionKeys performKeyExchangeAsServer(Socket socket) throws Exception {
        AlgorithmParameterGenerator pg = AlgorithmParameterGenerator.getInstance("DH");
        pg.init(1024);
        AlgorithmParameters params = pg.generateParameters();
        DHParameterSpec spec = params.getParameterSpec(DHParameterSpec.class);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(spec);
        KeyPair kp = kpg.generateKeyPair();

        sendBytes(socket, params.getEncoded());
        sendBytes(socket, kp.getPublic().getEncoded());

        byte[] clientPubEnc = receiveBytes(socket);
        PublicKey clientPub = KeyFactory.getInstance("DH")
                .generatePublic(new X509EncodedKeySpec(clientPubEnc));

        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(kp.getPrivate());
        ka.doPhase(clientPub, true);
        byte[] secret = ka.generateSecret();

        return deriveKeys(secret);
    }

    public static SessionKeys performKeyExchangeAsClient(Socket socket) throws Exception {
        byte[] paramsEnc = receiveBytes(socket);
        AlgorithmParameters params = AlgorithmParameters.getInstance("DH");
        params.init(paramsEnc);
        DHParameterSpec spec = params.getParameterSpec(DHParameterSpec.class);

        byte[] serverPubEnc = receiveBytes(socket);
        PublicKey serverPub = KeyFactory.getInstance("DH")
                .generatePublic(new X509EncodedKeySpec(serverPubEnc));

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(spec);
        KeyPair kp = kpg.generateKeyPair();

        sendBytes(socket, kp.getPublic().getEncoded());

        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(kp.getPrivate());
        ka.doPhase(serverPub, true);
        byte[] secret = ka.generateSecret();

        return deriveKeys(secret);
    }

    private static SessionKeys deriveKeys(byte[] secret) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-512").digest(secret);
        byte[] keyEnc = Arrays.copyOfRange(digest, 0, 32);
        byte[] keyMac = Arrays.copyOfRange(digest, 32, 64);
        SecretKey encKey = new SecretKeySpec(keyEnc, "AES");
        SecretKey macKey = new SecretKeySpec(keyMac, "HmacSHA256");
        return new SessionKeys(encKey, macKey);
    }

    public static byte[] receiveBytes(Socket socket) throws Exception {
        DataInputStream dis = new DataInputStream(socket.getInputStream());
        int len = dis.readInt();
        byte[] data = new byte[len];
        dis.readFully(data);
        return data;
    }

    public static void sendBytes(Socket socket, byte[] data) throws Exception {
        DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
        dos.writeInt(data.length);
        dos.write(data);
        dos.flush();
    }

    public static SignedMessage parseSignedMessage(byte[] payload) throws Exception {
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(payload));
        int ivLen = dis.readInt();
        byte[] iv = new byte[ivLen];
        dis.readFully(iv);
        int ctLen = dis.readInt();
        byte[] ct = new byte[ctLen];
        dis.readFully(ct);
        int sigLen = dis.readInt();
        byte[] sig = new byte[sigLen];
        dis.readFully(sig);
        return new SignedMessage(iv, ct, sig);
    }

    public static byte[] decryptAES(byte[] ct, SecretKey key, byte[] iv) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return c.doFinal(ct);
    }

    public static byte[] encryptAndHmac(byte[] plain, SessionKeys sk) throws Exception {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, sk.getEncryptionKey(), new IvParameterSpec(iv));
        byte[] ct = c.doFinal(plain);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(sk.getHmacKey());
        mac.update(iv);
        mac.update(ct);
        byte[] h = mac.doFinal();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos);
        dos.writeInt(iv.length); dos.write(iv);
        dos.writeInt(ct.length); dos.write(ct);
        dos.writeInt(h.length); dos.write(h);
        dos.flush();
        return bos.toByteArray();
    }

    public static byte[] decryptAndVerify(byte[] payload, SessionKeys sk) throws Exception {
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(payload));
        int ivLen = dis.readInt();
        byte[] iv = new byte[ivLen];
        dis.readFully(iv);
        int ctLen = dis.readInt();
        byte[] ct = new byte[ctLen];
        dis.readFully(ct);
        int hLen = dis.readInt();
        byte[] h = new byte[hLen];
        dis.readFully(h);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(sk.getHmacKey());
        mac.update(iv);
        mac.update(ct);
        byte[] expected = mac.doFinal();
        if (!MessageDigest.isEqual(expected, h)) {
            throw new SecurityException("Invalid HMAC");
        }
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, sk.getEncryptionKey(), new IvParameterSpec(iv));
        return c.doFinal(ct);
    }

    public static TablaServicios deserializeTable(byte[] bytes) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
        return (TablaServicios) ois.readObject();
    }
}
