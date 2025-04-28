import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

public class CifradoAsimetrico {

    public byte[] cifrar(byte[] datos, PublicKey llavePublica)throws Exception{

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, llavePublica);
        byte[] cifrado = cipher.doFinal(datos);
        return cifrado;

    }

    public byte[] descifrar(byte[] mensajeCifrado, PrivateKey llavePrivada) throws Exception{

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, llavePrivada);
        return cipher.doFinal(mensajeCifrado);

    }

}
