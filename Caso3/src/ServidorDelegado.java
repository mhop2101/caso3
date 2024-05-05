import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Random;

public class ServidorDelegado extends Thread{
    private Socket socket = null;
    private PrivateKey privateKey = null;
    private PublicKey publicKey = null;

    public ServidorDelegado(Socket socket, PrivateKey privateKey, PublicKey publicKey) {
        this.socket = socket;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public void run(){
        System.out.println("Servidor delegado creado");

        try{
            ObjectInputStream escritor = new ObjectInputStream(socket.getInputStream());
            ObjectOutputStream lector = new ObjectOutputStream(socket.getOutputStream());

            //Paso 2
            byte[] textoCifrado = paso2(escritor, lector);
            
            //Paso 3
            paso3(textoCifrado, escritor, lector);

            //Pre paso 6
            prePaso6(escritor, lector);

            //Paso 6 y 7
            paso6(escritor, lector);

        } catch (Exception e){
            e.printStackTrace();
            System.exit(-1);
        }
    }

    private byte[] paso2(ObjectInputStream pIn, ObjectOutputStream pOut) throws Exception {
        String reto = (String) pIn.readObject();
        System.out.println("Texto cifrado: " + reto);
        
        //Generar hash y cifrado
        byte[] hash = hash(reto);
        byte[] textoCifrado = CifrarDecifrar.CifrarAES(privateKey, reto, hash);

        return textoCifrado;
    }

    private void paso3(byte[] textoCifrado, ObjectInputStream pIn, ObjectOutputStream pOut){
        try{
            String strhex = CifrarDecifrar.bytesToHex(textoCifrado);
            pOut.writeObject(strhex);

            //Enviar llave publica
            pOut.writeObject(publicKey);
        } catch (Exception e){
            e.printStackTrace();
        }
    }

    private static void prePaso6(ObjectInputStream pIn, ObjectOutputStream pOut) throws Exception {
        String respuesta = (String) pIn.readObject();
        System.out.println("Recibe mensaje " + respuesta);
    }

    private void paso6(ObjectInputStream pIn, ObjectOutputStream pOut) throws Exception {
        String g = "2";
        String p = "00dd8922190d814d016f28ad5b7b965b4b8cd7ac3defbe234fb57ed951c30596f648824bef16b4faa3700a5e2304ec0101c72da493d3d6cecfbfdf5b4634bf8fc92a769d7716ca82afdab111da1750c67f256329f69738961804a3f7c68c32716174482dc9bdff08d17ee4530ac3e3f0298104d99799a37acf742a23e1c6611d0f";
        String iv = "9372546801234875";
        BigInteger x = BigInteger.valueOf(new java.util.Random().nextInt(20));

        //Generar G^x
        BigInteger base = new BigInteger(g);
        BigInteger exponent = x;
        BigInteger modulus = new BigInteger(p, 16);
        BigInteger gx = base.modPow(exponent, modulus);


        //Enviamos g, p, Gx y iv sin cifrar
        pOut.writeObject(g);
        pOut.writeObject(p);
        pOut.writeObject(gx);
        pOut.writeObject(iv);

        //Enviamos g, p y gx cifrados
        String pgx = g + ";" + p + ";" + gx.toString();

        byte[] pgxhash = CifrarDecifrar.stringToHash(pgx);
        System.out.println("hash pgx" + pgxhash);
        byte[] pgxcipher = CifrarDecifrar.CifrarAESConHash(privateKey, pgxhash);
        
        System.out.println("cifrado pgx" + pgxcipher);

        //Convertirlos en hexa el cifrado
        String pgxcipherhex = CifrarDecifrar.bytesToHex(pgxcipher);
        System.out.println("cifrado pgx hex: " + pgxcipherhex);
        pOut.writeObject(pgxcipherhex);
        

        //Enviar llave publica
        pOut.writeObject(publicKey);
    }

    private static byte[] hash(String mensaje) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(mensaje.getBytes());

        return hash;
    }
    
}
