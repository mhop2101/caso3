import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

import java.security.SecureRandom;
import java.util.Map;



public class Cliente {
    public static final int PUERTO = 3400;
	public static final String SERVIDOR = "localhost";

	// Caracteres válidos para generar el nombre de usuario y la contraseña
    private static final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	
	public static void main(String[] args) throws Exception {
		
		Socket socket = null;
		ObjectOutputStream escritor = null;
		ObjectInputStream lector = null;
		
		System.out.println("Comienza cliente");
		
		try {
            System.out.println("llege aqui1");
			socket = new Socket(SERVIDOR, PUERTO);
            System.out.println("llege aqui414124");
			escritor = new ObjectOutputStream(socket.getOutputStream());
            System.out.println("llege aqui9999");
            lector = new ObjectInputStream(socket.getInputStream());
            System.out.println("llege aqui2");
		}
		catch (Exception e) {
			e.printStackTrace();
            System.exit(-1);
		}
		System.out.println("llege aqui3");
		BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
        //enviar el mensaje al servidor

        //Crear numero de reto
        SecureRandom random = new SecureRandom();
        int var = Math.abs(random.nextInt());
        String numeroAleatorio = Integer.toString(var);
        System.out.println("llege aqui4");
        ProtocoloCliente.paso1(lector, escritor, numeroAleatorio);

        escritor.close();
		lector.close();
		socket.close();
		stdIn.close();
    }

}