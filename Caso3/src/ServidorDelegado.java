import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ServidorDelegado extends Thread{
    private Socket socket = null;
    private PrivateKey privateKey = null;
    private PublicKey publicKey = null;
    private static final String login = "miguel";
    private static final String contrasena = "barkley";

    public ServidorDelegado(Socket socket, PrivateKey privateKey, PublicKey publicKey) {
        this.socket = socket;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public void run(){
        System.out.println("\nServidor delegado creado\n");

        try{
            ObjectInputStream escritor = new ObjectInputStream(socket.getInputStream());
            ObjectOutputStream lector = new ObjectOutputStream(socket.getOutputStream());

            //Paso 2
            byte[] textoCifrado = paso2(escritor, lector);
            
            //Paso 3
            paso3(textoCifrado, escritor, lector);

            //Pre paso 6
            prePaso6(escritor, lector);

            //Paso 6, 7, 9 y 10
            ArrayList<BigInteger> lista = paso6_9_10(escritor, lector);
            BigInteger numMagic = lista.get(0);
            BigInteger ivB = lista.get(1);

            //Paso 11 Dentro del main
            byte[] llaveByte = CifrarDecifrar.stringToHash(numMagic.toString());
            int mitad = llaveByte.length / 2;

            //preK_AB1
            byte[] prek_ab1 = Arrays.copyOfRange(llaveByte, 0, mitad);

            //preK_AB2
            byte[] prek_ab2 = Arrays.copyOfRange(llaveByte, mitad, llaveByte.length);

            //Llaves simetricas
            SecretKey kab1 = new SecretKeySpec(prek_ab1, "AES");
            SecretKey kab2 = new SecretKeySpec(prek_ab2, "HmacSHA256");
            
            lector.writeObject("CONTINUAR");
            System.out.println("Servidor escribe mensaje CONTINUAR (Paso 12)\n");

            //Paso 15 y 16
            String iv = ivB.toString();
            paso15_16(escritor, lector, kab1, kab2, iv);

            //Paso 19 y 20
            paso19_20(escritor, lector, kab1, kab2, iv);

        } catch (Exception e){
            e.printStackTrace();
            System.exit(-1);
        }
    }

    private byte[] paso2(ObjectInputStream pIn, ObjectOutputStream pOut) throws Exception {
        long tiempoInicial = System.currentTimeMillis();
        String reto = (String) pIn.readObject();
        System.out.println("Texto cifrado: " + reto + "\n");
        
        //Generar hash y cifrado
        byte[] hash = hash(reto);
        byte[] textoCifrado = CifrarDecifrar.CifrarAES(privateKey, reto, hash);
        long tiempoFinal = System.currentTimeMillis();
        System.out.println("########## Tiempo para generar la firma: " + (tiempoFinal - tiempoInicial) + " ms\n");


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
        System.out.println("Recibe mensaje " + respuesta + " (Paso 5)\n");
    }

    private ArrayList<BigInteger> paso6_9_10(ObjectInputStream pIn, ObjectOutputStream pOut) throws Exception {
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
        byte[] pgxcipher = CifrarDecifrar.CifrarAESConHash(privateKey, pgxhash);
        pOut.writeObject(pgxcipher);

        //Enviar llave publica
        pOut.writeObject(publicKey);
        
        //Recibir respuesta
        boolean respuesta = (boolean) pIn.readObject();
        if(respuesta){
            System.out.println("Recibe mensaje OK (Paso 9)\n");
        } else {
            System.out.println("Recibe mensaje ERROR (Paso 9)\n");
        }

        //Gemerar Gy ^x
        BigInteger gy = (BigInteger) pIn.readObject();
        BigInteger gyx = gy.modPow(x, modulus);
        BigInteger ivB = new BigInteger(iv);
        ArrayList<BigInteger> list = new ArrayList<>();
        list.add(gyx);
        list.add(ivB);
        return list;
    }

    private void paso15_16(ObjectInputStream pIn, ObjectOutputStream pOut, SecretKey kab1, SecretKey kab2, String iv) throws Exception {
        byte[] loginllega = (byte[]) pIn.readObject();
        byte[] contraseniallega = (byte[]) pIn.readObject();

        byte[] loginCifrado = CifrarDecifrar.CifrarSimetrico(kab1, iv, CifrarDecifrar.stringToHash(login));
        byte[] contrasenaCifrado = CifrarDecifrar.CifrarSimetrico(kab1, iv, CifrarDecifrar.stringToHash(contrasena));

        String strLoginLlega = Arrays.toString(loginllega);
        String strContrasenaLlega = Arrays.toString(contraseniallega);

        String strLoginCifrado = Arrays.toString(loginCifrado);
        String strContrasenaCifrado = Arrays.toString(contrasenaCifrado);
        
        if(strLoginLlega.equals(strLoginCifrado) && strContrasenaLlega.equals(strContrasenaCifrado)){
            System.out.println("Enviar OK Log y Con (Paso 16)\n");
            pOut.writeObject("OK");
        } else {
            System.out.println("Enviar error Log y Con (Paso 16)\n");
            pOut.writeObject("ERROR");
        }
    }

    private void paso19_20(ObjectInputStream pIn, ObjectOutputStream pOut, SecretKey kab1, SecretKey kab2, String iv) throws Exception {
        long tiempoInicial = System.currentTimeMillis();
        byte[] numeroConsultaCifrado = (byte[]) pIn.readObject();
        byte[] hmac = (byte[]) pIn.readObject();

        byte[] numeroConsulta = CifrarDecifrar.DescifrarSimetrico(kab1, iv, numeroConsultaCifrado);

        String reconstructedString = new String(numeroConsulta);
        long tiempoFinal = System.currentTimeMillis();
        int rta = Integer.parseInt(reconstructedString);
        rta--;
        String strRta = Integer.toString(rta);
        System.out.println("Numero de consulta - 1 / rta (Actualizado y enviado): " + strRta + " (Paso 19)\n");
        System.out.println("########## Tiempo total para decifrar la consulta: " + (tiempoFinal - tiempoInicial) + " ms\n");

        //Generar cifrado de rta
        long tiempoInicialCifrado = System.currentTimeMillis();
        byte[] rtaByte = strRta.getBytes(StandardCharsets.UTF_8);
        byte[] rtaCifrada = CifrarDecifrar.CifrarSimetrico(kab1, iv, rtaByte);

        //Enviar numero de consulta cifrado
        pOut.writeObject(rtaCifrada);

        //Generar hmac
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(kab2);
        byte[] hmacRta = mac.doFinal(rtaByte);

        //Enviar HMAC
        long tiempoFinalCifrado = System.currentTimeMillis();
        pOut.writeObject(hmacRta);
        System.out.println("########## Tiempo total para verificar codigo de autenticacion: " + (tiempoFinalCifrado - tiempoInicialCifrado) + " ms\n");
    }

    private static byte[] hash(String mensaje) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(mensaje.getBytes());

        return hash;
    }
    
}
