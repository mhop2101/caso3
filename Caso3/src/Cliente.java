import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;




public class Cliente {
    public static final int PUERTO = 3400;
	public static final String SERVIDOR = "localhost";

	
	public static void main(String[] args) throws Exception {
		String login = "miguel";
        String contrasena = "barkley";
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
        ArrayList<BigInteger> list = paso8_9_10(lector, escritor);
        BigInteger numMagic = list.get(0);
        BigInteger ivB = list.get(1);

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
        System.out.println("Cliente recibe mensaje " + cont + " (Paso 12)\n");

        //Paso 13 y 14
        String iv = ivB.toString(); 
        paso13_14(lector, escritor, kab1, login, contrasena, iv);

        //Paso 16
        String mensaje = (String) lector.readObject();
        System.out.println("Recibe mensaje " + mensaje + " (Paso 16)\n");

        //Paso 17 y 18
        paso17_18(lector, escritor, kab1, kab2, iv);

        //Paso 21
        paso21(lector, escritor, kab1, kab2, iv);

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
        long tiempoInicial = System.currentTimeMillis();
        String retoCifrado = (String) pIn.readObject();
        PublicKey publicKey = (PublicKey) pIn.readObject();
        
        byte[] byteCifrado = CifrarDecifrar.hexToBytes(retoCifrado);
        byte[] byteDescifrado = CifrarDecifrar.DescifrarAES(publicKey, byteCifrado);

        String retoDecifrado = new String(byteDescifrado);
        System.out.println("Reto recibido y decifrado: " + retoDecifrado + "\n");
        long tiempoFinal = System.currentTimeMillis();
        long tiempoTotal = tiempoFinal - tiempoInicial;
        System.out.println("########## Tiempo total para decifrar reto: " + tiempoTotal + " ms \n");
        return retoDecifrado;
    }

    private static ArrayList<BigInteger> paso8_9_10(ObjectInputStream pIn, ObjectOutputStream pOut) throws Exception {
        long tiempoInicial = System.currentTimeMillis();
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
        long tiempoFinal = System.currentTimeMillis();
        long tiempoTotal = tiempoFinal - tiempoInicial;
        System.out.println("########## Tiempo total para generar G^y: " + tiempoTotal + " ms \n");
        //Enviamos Gy
        pOut.writeObject(gy);

        //Generar Gx^y
        BigInteger gxy = gx.modPow(y, modulus);
        BigInteger ivB = new BigInteger(iv);
        ArrayList<BigInteger> list = new ArrayList<>();
        list.add(gxy);
        list.add(ivB);
        return list;
    }

    private static void paso13_14(ObjectInputStream pIn, ObjectOutputStream pOut, SecretKey kab1, String login, String contrasena, String iv) throws Exception {
        byte[] loginCifrado = CifrarDecifrar.CifrarSimetrico(kab1, iv, CifrarDecifrar.stringToHash(login));
        byte[] contraseniaCifrado = CifrarDecifrar.CifrarSimetrico(kab1, iv, CifrarDecifrar.stringToHash(contrasena));

        pOut.writeObject(loginCifrado);
        pOut.writeObject(contraseniaCifrado);
    }

    private static void paso17_18(ObjectInputStream pIn, ObjectOutputStream pOut, SecretKey kab1, SecretKey kab2, String iv) throws Exception {
        long tiempoInicial = System.currentTimeMillis();
        //Generar numero de consulta
        Random random = new Random();
        int numeroConsulta = random.nextInt(10000);
        String numCon = Integer.toString(numeroConsulta);

        //Cifrar numero de consulta
        System.out.println("Numero de consulta: " + numeroConsulta + " (Paso 17)\n");
        byte[] nConByte = numCon.getBytes(StandardCharsets.UTF_8);

        byte[] numeroConsultaCifrado = CifrarDecifrar.CifrarSimetrico(kab1, iv, nConByte);
        long tiempoFinal = System.currentTimeMillis();
        long tiempoTotal = tiempoFinal - tiempoInicial;
        System.out.println("########## Tiempo total para cifrar numero de consulta: " + tiempoTotal + " ms \n");
        //Enviar numero de consulta cifrado
        pOut.writeObject(numeroConsultaCifrado);

        //Generar HMAC de la consulta con k_AB2
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(kab2);
        byte[] hmac = mac.doFinal(nConByte); 

        //Enviar HMAC
        pOut.writeObject(hmac);
    }

    private static void paso21(ObjectInputStream pIn, ObjectOutputStream pOut, SecretKey kab1, SecretKey kab2, String iv) throws Exception {
        //Recibir rta y hmac

        byte[] rtaCifrada = (byte[]) pIn.readObject();
        byte[] hmac = (byte[]) pIn.readObject();

        //Descifrar rta
        byte[] rtaByte = CifrarDecifrar.DescifrarSimetrico(kab1, iv, rtaCifrada);
        String rta = new String(rtaByte);
        System.out.println("Recibir respuesta: " + rta + " (Paso 19)\n");
        long tiempoInicial = System.currentTimeMillis();
        //Generar hmac de rtaByte
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(kab2);
        byte[] hmacRta = mac.doFinal(rtaByte);

        if(Arrays.toString(hmacRta).equals(Arrays.toString(hmac))){
            System.out.println("HMAC Correcto (Paso 21)\n");
            long tiempoFinal = System.currentTimeMillis();
            long tiempoTotal = tiempoFinal - tiempoInicial;
            System.out.println("########## Tiempo total para verificar HMAC: " + tiempoTotal + " ms \n");
        } else {
            System.out.println("HMAC Incorrecto (Paso 21)\n");
        }
    }
}