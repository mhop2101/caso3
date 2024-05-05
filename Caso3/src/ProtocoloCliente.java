import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class ProtocoloCliente {
    
    public static void paso1(ObjectInputStream pIn, ObjectOutputStream pOut,String numeroAleatorio) throws Exception {
        long tiempoInicial = System.currentTimeMillis();
        pOut.writeObject(numeroAleatorio);
        System.out.println("Reto: " + numeroAleatorio);
        
    }

}
