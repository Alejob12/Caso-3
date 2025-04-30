package Escenario;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.Arrays;

public class MedicionCifrado {

    public static void main(String[] args) throws Exception {
        int repeticiones = 1000;
        int tamanoMensaje = 32; 

        byte[] mensaje = new byte[tamanoMensaje];
        SecureRandom random = new SecureRandom();
        random.nextBytes(mensaje);

        KeyGenerator keyGenAES = KeyGenerator.getInstance("AES");
        keyGenAES.init(256); 
        SecretKey llaveAES = keyGenAES.generateKey();
        Cipher cifradorAES = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        
        KeyPairGenerator keyGenRSA = KeyPairGenerator.getInstance("RSA");
        keyGenRSA.initialize(1024); // Clave de 1024 bits para RSA
        KeyPair parRSA = keyGenRSA.generateKeyPair();
        Cipher cifradorRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        long inicioAES = System.nanoTime();
        for (int i = 0; i < repeticiones; i++) {
            cifradorAES.init(Cipher.ENCRYPT_MODE, llaveAES, ivSpec);
            byte[] cifrado = cifradorAES.doFinal(mensaje);
        }
        long finAES = System.nanoTime();

        double tiempoTotalAES = (finAES - inicioAES) / 1_000_000_000.0; 
        double opsPorSegundoAES = repeticiones / tiempoTotalAES;

        System.out.println("AES - Tiempo total: " + tiempoTotalAES + " segundos");
        System.out.println("AES - Operaciones por segundo: " + opsPorSegundoAES);

        long inicioRSA = System.nanoTime();
        for (int i = 0; i < repeticiones; i++) {
            cifradorRSA.init(Cipher.ENCRYPT_MODE, parRSA.getPublic());
            byte[] cifrado = cifradorRSA.doFinal(mensaje);
        }
        long finRSA = System.nanoTime();

        double tiempoTotalRSA = (finRSA - inicioRSA) / 1_000_000_000.0; // Segundos
        double opsPorSegundoRSA = repeticiones / tiempoTotalRSA;

        System.out.println("RSA - Tiempo total: " + tiempoTotalRSA + " segundos");
        System.out.println("RSA - Operaciones por segundo: " + opsPorSegundoRSA);
    }
}

