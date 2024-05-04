import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public class Servidor {
    private static final int PUERTO = 3400;

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {

        //Servidor iniciado
        ServerSocket ss = null;
        boolean continuar = true;

        System.out.println("Main server ...");

        try{
            ss = new ServerSocket(PUERTO);
        } catch (IOException e){
            System.err.println("no se pudo crear el socket con el puerto: " + PUERTO);
            System.exit(-1);
        }

        while(continuar){
            //creación de servidores delegados
            Socket socket  = ss.accept();

            //TODO: crear un hilo para el servidor delegado
        }
        ss.close();
    }
}
