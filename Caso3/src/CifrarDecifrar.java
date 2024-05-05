import java.security.Key;
import java.security.PrivateKey;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CifrarDecifrar {
    private final static String AES = "RSA";
    private final static String PADDING = "AES/CBC/PKCS5Padding";

    public static byte[] CifrarAES(PrivateKey llave, String texto, byte[] hash) {
        byte[] textoCifrado;
        try {
            Cipher cifrador = Cipher.getInstance(AES);
            byte[] textoClaro = texto.getBytes();

            cifrador.init(Cipher.ENCRYPT_MODE, llave);
            textoCifrado = cifrador.doFinal(textoClaro);
            return textoCifrado;
        } catch (Exception e) {
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

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(0xff & bytes[i]);
            if (hex.length() == 1)
                hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static byte[] hexToBytes(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2]; // Cada dos caracteres forman un byte
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }
        return data;
    }
    
}
