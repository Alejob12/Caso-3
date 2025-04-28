import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CifradoSimetrico {

    public byte[] cifrar(byte[] mensaje, byte[] clave) throws Exception{

        SecretKeySpec llaveAES = new SecretKeySpec(clave, "AES");

        byte[] iv = this.generarIV();
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        System.out.println(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, llaveAES, ivSpec);
        
        byte[] cifrado = cipher.doFinal(mensaje);
        System.out.println(cifrado);
        byte[] resultado = new byte[iv.length + cifrado.length];

        System.arraycopy(iv, 0, resultado, 0, iv.length);
        System.arraycopy(cifrado, 0, resultado, iv.length, cifrado.length);

        return resultado;//iv+cifrado

    }

    public byte[] descifrar( byte[] datos, byte[] clave) throws Exception{

        byte[] iv = new byte[16];
        System.arraycopy(datos, 0, iv, 0, 16);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        int tamCifrado = datos.length - 16;
        byte[] mensajeCifrado = new byte[tamCifrado];
        System.arraycopy(datos, 16, mensajeCifrado, 0, tamCifrado);

        SecretKeySpec llaveAES = new SecretKeySpec(clave, "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, llaveAES, ivSpec);
        //descifrar
        byte[] mensajeD = cipher.doFinal(mensajeCifrado);
        return mensajeD;


    }

    public byte[] generarIV(){

        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        return iv;
    }

}
