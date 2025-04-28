import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.*;
import java.util.Base64;
import java.util.stream.Collectors;

public class GestorLlaves {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public GestorLlaves(String privateKeyPath, String publicKeyPath) throws Exception {
        if (privateKeyPath != null) {
            this.privateKey = loadPrivateKey(privateKeyPath);
        }
        if (publicKeyPath != null) {
            this.publicKey = loadPublicKey(publicKeyPath);
        }
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    private PrivateKey loadPrivateKey(String path) throws Exception {
        byte[] bytes = Files.readAllBytes(Paths.get(path));
        if (isPem(bytes, "PRIVATE KEY")) {
            bytes = parsePem(bytes, "PRIVATE KEY");
        }
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    private PublicKey loadPublicKey(String path) throws Exception {
        byte[] bytes = Files.readAllBytes(Paths.get(path));
        if (isPem(bytes, "PUBLIC KEY")) {
            bytes = parsePem(bytes, "PUBLIC KEY");
        }
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    private boolean isPem(byte[] data, String type) {
        String s = new String(data);
        return s.contains("-----BEGIN " + type + "-----");
    }

    private byte[] parsePem(byte[] pemBytes, String type) throws IOException {
        String pem = new String(pemBytes);
        String header = "-----BEGIN " + type + "-----";
        String footer = "-----END " + type + "-----";
        String base64 = pem
                .replace(header, "")
                .replace(footer, "")
                .lines()
                .filter(line -> !line.startsWith("-----"))
                .collect(Collectors.joining());
        return Base64.getDecoder().decode(base64);
    }
}

