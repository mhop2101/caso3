import java.security.Key;
import java.security.PrivateKey;

import javax.crypto.Cipher;

public class CifrarDecifrar {
    private final static String AES = "RSA";
    //private final static String PADDING = "AES/CBC/PKCS5Padding";

    public static byte[] CifrarAES(Key llave, String texto){
        byte[] textoCifrado;  

        try{
            Cipher cifrador = Cipher.getInstance(AES);
            byte[] textoClaro = texto.getBytes();

            cifrador.init(Cipher.ENCRYPT_MODE, llave);
            textoCifrado = cifrador.doFinal(textoClaro);

            return textoCifrado;
        } catch (Exception e){
            System.out.println("Exception: " + e.getMessage());
            return null;
        }
    }
    
    public static byte[] DescifrarAES(Key llave, byte[] texto){
        byte[] textoClaro;

        try{
            Cipher cifrador = Cipher.getInstance(AES);  
            
            cifrador.init(Cipher.DECRYPT_MODE, llave);
            textoClaro = cifrador.doFinal(texto);
        } catch (Exception e){
            System.out.println("Exception: " + e.getMessage());
            return null;
        }
        return textoClaro;
    }

    
}
