import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Servidor {
    private static final int PUERTO = 3400;
    private static PrivateKey privateKey;
    public static PublicKey publicKey;

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {

        //Servidor iniciado
        ServerSocket ss = null;
        boolean continuar = true;

        //Generación de llaves
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        KeyPair pair = keyGen.generateKeyPair();
        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();

        //Conteo de servidores
        int servidores = 0;
        System.out.println("Main server ...");

        try{
            ss = new ServerSocket(PUERTO);
        } catch (IOException e){
            System.err.println("no se pudo crear el socket con el puerto: " + PUERTO);
            System.exit(-1);
        }

        while(continuar){
            //Creación de servidores delegados
            Socket socket  = ss.accept();
            Thread t = new Thread(new ServidorDelegado(socket, privateKey, publicKey));
            t.start();
            servidores++;
        }
        ss.close();
    }
}
