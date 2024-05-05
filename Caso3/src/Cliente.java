import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;



public class Cliente {
    public static final int PUERTO = 3400;
	public static final String SERVIDOR = "localhost";
    private static final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	
	public static void main(String[] args) throws Exception {
		
		Socket socket = null;
		ObjectOutputStream escritor = null;
		ObjectInputStream lector = null;
		
		System.out.println("Comienza cliente\n");
		
		try {
			socket = new Socket(SERVIDOR, PUERTO);
			escritor = new ObjectOutputStream(socket.getOutputStream());
            lector = new ObjectInputStream(socket.getInputStream());
		}
		catch (Exception e) {
			e.printStackTrace();
            System.exit(-1);
		}
		BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));

        //Crear numero de reto y enviarlo
        SecureRandom random = new SecureRandom();
        int var = Math.abs(random.nextInt());
        String numeroAleatorio = Integer.toString(var);

        //Paso 1
        paso1(lector, escritor, numeroAleatorio);

        //Paso 4 y 5
        String retoDevuleto = paso4(lector, escritor);
        if(retoDevuleto.equals(numeroAleatorio)){
            System.out.println("Enviado mensaje OK (Paso 4-5)\n");
            escritor.writeObject("OK");
        } else {
            System.out.println("Enviado mensaje ERROR (Paso 4-5)\n");
            escritor.writeObject("ERROR");
        }

        //Paso 8, 9 y 10 
        BigInteger numMagic = paso8_9_10(lector, escritor);

        //Paso 11 en el main
        byte[] llaveByte = CifrarDecifrar.stringToHash(numMagic.toString());
        int mitad = llaveByte.length / 2;

        //preK_AB1
        byte[] prek_ab1 = Arrays.copyOfRange(llaveByte, 0, mitad);

        //preK_AB2
        byte[] prek_ab2 = Arrays.copyOfRange(llaveByte, mitad, llaveByte.length);

        //Llaves simetricas
        SecretKey kab1 = new SecretKeySpec(prek_ab1, "AES");
        SecretKey kab2 = new SecretKeySpec(prek_ab2, "HmacSHA256");

        String cont = (String) lector.readObject();
        System.out.println("Cliente recibe mensaje " + cont + "\n");


        escritor.close();
		lector.close();
		socket.close();
		stdIn.close();
    }

    private static void paso1(ObjectInputStream pIn, ObjectOutputStream pOut,String numeroAleatorio) throws Exception {
        long tiempoInicial = System.currentTimeMillis();
        pOut.writeObject(numeroAleatorio);
        System.out.println("Reto enviado: " + numeroAleatorio + "\n");
        
    }

    private static String paso4(ObjectInputStream pIn, ObjectOutputStream pOut) throws Exception {
        String retoCifrado = (String) pIn.readObject();
        PublicKey publicKey = (PublicKey) pIn.readObject();
        
        byte[] byteCifrado = CifrarDecifrar.hexToBytes(retoCifrado);
        byte[] byteDescifrado = CifrarDecifrar.DescifrarAES(publicKey, byteCifrado);

        String retoDecifrado = new String(byteDescifrado);
        System.out.println("Reto recibido y decifrado: " + retoDecifrado + "\n");

        return retoDecifrado;
    }

    private static BigInteger paso8_9_10(ObjectInputStream pIn, ObjectOutputStream pOut) throws Exception {
        String g = (String) pIn.readObject();
        String p = (String) pIn.readObject();
        BigInteger gx = (BigInteger) pIn.readObject();
        String iv = (String) pIn.readObject();
        byte[] bytePGX = (byte[]) pIn.readObject();
        PublicKey publicKey = (PublicKey) pIn.readObject();

        //Decfirar pgx
        byte[] byteDescifradoPGX = CifrarDecifrar.DescifrarAES(publicKey, bytePGX);

        //Crear hash local
        String pgx = g + ";" + p + ";" + gx.toString();
        byte[] pgxhash = CifrarDecifrar.stringToHash(pgx);
        
        if(Arrays.toString(byteDescifradoPGX).equals(Arrays.toString(pgxhash))){
            System.out.println("Enviado mensaje OK (Paso 8-9)\n");
            pOut.writeObject(true);;
        } else {
            System.out.println("Enviado mensaje ERROR (Paso 8-9)\n");
            pOut.writeObject(false);;
        }

        //Paso 10
        BigInteger y = BigInteger.valueOf(new java.util.Random().nextInt(20));
        BigInteger base = new BigInteger(g);
        BigInteger exponent = y;
        BigInteger modulus = new BigInteger(p, 16);
        BigInteger gy = base.modPow(exponent, modulus);

        //Enviamos Gy
        pOut.writeObject(gy);

        //Generar Gx^y
        BigInteger gxy = gx.modPow(y, modulus);
        return gxy;
    }

}