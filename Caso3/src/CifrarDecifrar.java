import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class CifrarDecifrar {
    private final static String RSA = "RSA";
    private final static String PADDING = "AES/CBC/PKCS5Padding";

    public static byte[] CifrarAES(PrivateKey llave, String texto, byte[] hash) {
        byte[] textoCifrado;
        try {
            Cipher cifrador = Cipher.getInstance(RSA);
            byte[] textoClaro = texto.getBytes();

            cifrador.init(Cipher.ENCRYPT_MODE, llave);
            textoCifrado = cifrador.doFinal(textoClaro);
            return textoCifrado;
        } catch (Exception e) {
            System.out.println("Exception AES sencillo: " + e.getMessage());
            return null;
        }
    }

    public static byte[] CifrarAESArray(PrivateKey llave, BigInteger texto, byte[] hash) {
        byte[] textoCifrado;
        try {
            Cipher cifrador = Cipher.getInstance(RSA);
            byte[] textoClaro = texto.toByteArray();

            cifrador.init(Cipher.ENCRYPT_MODE, llave);
            textoCifrado = cifrador.doFinal(textoClaro);
            return textoCifrado;
        } catch (Exception e) {
            System.out.println("Exception AES array: " + e.getMessage());
            return null;
        }
    }

    public static byte[] CifrarAESConHash(PrivateKey llave, byte[] hash) {
        byte[] textoCifrado;
        try {
            Cipher cifrador = Cipher.getInstance(RSA);

            cifrador.init(Cipher.ENCRYPT_MODE, llave);
            textoCifrado = cifrador.doFinal(hash);
            return textoCifrado;
        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
            return null;
        }
    }

    public static byte[] CifrarSimetrico(SecretKey llave, String iv, byte[] texto) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException{
        byte[] datoCifrado;

        Cipher cipher = Cipher.getInstance(PADDING);
        SecretKey sk = llave;
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, sk, ivParameterSpec);
        datoCifrado = cipher.doFinal(texto);

        return datoCifrado;
    }
    
    public static byte[] DescifrarAES(Key llave, byte[] texto){
        byte[] textoClaro;

        try{
            Cipher cifrador = Cipher.getInstance(RSA);  
            
            cifrador.init(Cipher.DECRYPT_MODE, llave);
            textoClaro = cifrador.doFinal(texto);
        } catch (Exception e){
            System.out.println("Exception decifrar : " + e.getMessage());
            return null;
        }
        return textoClaro;
    }

    public static byte[] DescifrarSimetrico(SecretKey llave, String iv, byte[] texto) throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        byte[] textoClaro;

        Cipher cipher = Cipher.getInstance(PADDING);
        SecretKey sk = llave;
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, sk, ivParameterSpec);
        textoClaro = cipher.doFinal(texto);
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
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                                 + Character.digit(hexString.charAt(i+1), 16));
        }
        return data;
    }

    public static byte[] stringToHash(String mensaje) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(mensaje.getBytes());

        return hashBytes;
    }
    
}
