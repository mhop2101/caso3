import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Map;



public class Cliente {
    public static final int PUERTO = 3400;
	public static final String SERVIDOR = "localhost";
    private PublicKey publicKey = null;
    private String numeroAleatorio = null;
    private static final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	
	public static void main(String[] args) throws Exception {
		
		Socket socket = null;
		ObjectOutputStream escritor = null;
		ObjectInputStream lector = null;
		
		System.out.println("Comienza cliente");
		
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
            System.out.println("Enviado mensaje OK");
            escritor.writeObject("OK");
        } else {
            System.out.println("Enviado mensaje ERROR");
            escritor.writeObject("ERROR");
        }

        //Paso 8
        paso8(lector, escritor);

        escritor.close();
		lector.close();
		socket.close();
		stdIn.close();
    }

    public static void paso1(ObjectInputStream pIn, ObjectOutputStream pOut,String numeroAleatorio) throws Exception {
        long tiempoInicial = System.currentTimeMillis();
        pOut.writeObject(numeroAleatorio);
        System.out.println("Reto: " + numeroAleatorio);
        
    }

    public static String paso4(ObjectInputStream pIn, ObjectOutputStream pOut) throws Exception {
        String retoCifrado = (String) pIn.readObject();
        PublicKey publicKey = (PublicKey) pIn.readObject();
        
        byte[] byteCifrado = CifrarDecifrar.hexToBytes(retoCifrado);
        byte[] byteDescifrado = CifrarDecifrar.DescifrarAES(publicKey, byteCifrado);

        String retoDecifrado = new String(byteDescifrado);

        return retoDecifrado;
    }

    public static void paso8(ObjectInputStream pIn, ObjectOutputStream pOut) throws Exception {
        String g = (String) pIn.readObject();
        String p = (String) pIn.readObject();
        // BigInteger gx = new BigInteger((String) pIn.readObject());
        String iv = (String) pIn.readObject();

        // String hexPG = (String) pIn.readObject();
        // String hexGX = (String) pIn.readObject();

        PublicKey publicKey = (PublicKey) pIn.readObject();

        // byte[] bytePG = CifrarDecifrar.hexToBytes(hexPG);
        // byte[] byteGX = CifrarDecifrar.hexToBytes(hexGX);

        // byte[] byteDescifradoPG = CifrarDecifrar.DescifrarAES(publicKey, bytePG);
        // byte[] byteDescifradoGX = CifrarDecifrar.DescifrarAES(publicKey, byteGX);

        System.out.println(g);
        System.out.println(p);
        // System.out.println(gx.toString());
        System.out.println(iv);
        // System.out.println(new String(byteDescifradoPG));
        // System.out.println(new String(byteDescifradoGX));

    }

}