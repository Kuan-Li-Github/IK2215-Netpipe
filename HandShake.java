import java.io.FileInputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;

public class HandShake {

    Socket handshakeSocket;
    Arguments handshakearguments;
    public SessionCipher sessionCipher;
    private HandshakeCertificate clientCertificate;
    private HandshakeCertificate serverCertificate;
    private HandshakeCertificate caCertificate;
    private final Integer keylength = 128;
    private final Integer timelimit =120;

    public HandShake(Socket socket,Arguments arguments) {

        handshakeSocket = socket;
        handshakearguments = arguments;

    }
    public void doClientHandshake() throws Exception {

        //send client hello
        FileInputStream instream1 = new FileInputStream(handshakearguments.get("usercert"));
        clientCertificate = new HandshakeCertificate(instream1);
        HandshakeMessage clientHello = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
        clientHello.putParameter("Certificate",
                Base64.getEncoder().encodeToString(clientCertificate.getBytes()));
        clientHello.send(handshakeSocket);
        System.out.println("send client hello");

        //receive server hello
        HandshakeMessage serverHello = HandshakeMessage.recv(handshakeSocket);
        if (!serverHello.getType().equals(HandshakeMessage.MessageType.SERVERHELLO)) {
            throw new Exception("Did not understand message");
        }
        FileInputStream instream2 = new FileInputStream(handshakearguments.get("cacert"));
        caCertificate = new HandshakeCertificate(instream2);
        byte[] bytearray = Base64.getDecoder().decode(serverHello.getParameter("Certificate"));
        serverCertificate = new HandshakeCertificate(bytearray);
        serverCertificate.verify(caCertificate);
        System.out.println("receive server hello from "+serverCertificate.getCN());

        //send session key and IV
        SessionKey sessionKey = new SessionKey(keylength);
        sessionCipher = new SessionCipher(sessionKey);
        HandshakeCrypto serverCrypto = new HandshakeCrypto(serverCertificate);
        HandshakeMessage clientsessionparameter = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);
        clientsessionparameter.putParameter("SessionKey",
                Base64.getEncoder().encodeToString(serverCrypto.encrypt(sessionCipher.getSessionKey().getKeyBytes())));
        clientsessionparameter.putParameter("SessionIV",
                Base64.getEncoder().encodeToString(serverCrypto.encrypt(sessionCipher.getIVBytes())));
        clientsessionparameter.send(handshakeSocket);
        System.out.println("client send session parameter");

        //receive server Finished
        HandshakeMessage serverFinished = HandshakeMessage.recv(handshakeSocket);
        if (!serverFinished.getType().equals(HandshakeMessage.MessageType.SERVERFINISHED)) {
            throw new Exception("Did not understand message");
        }
        byte[] signature = serverCrypto.decrypt(Base64.getDecoder().decode(serverFinished.getParameter("Signature")));
        byte[] timestamprecv = serverCrypto.decrypt(Base64.getDecoder().decode(serverFinished.getParameter("TimeStamp")));

        SimpleDateFormat timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date timerecv = timestamp.parse(new String(timestamprecv, StandardCharsets.UTF_8));
        Date nowTime = new Date();
        long difference = (nowTime.getTime()-timerecv.getTime())/1000;
        if(difference>timelimit){
            throw new Exception("this message is old");
        }

        HandshakeDigest testHandshakeDigest = new HandshakeDigest();
        testHandshakeDigest.update(serverHello.getBytes());
        if(!HandshakeDigest.isEqual(testHandshakeDigest.digest(),signature)){
            throw new Exception("wrong signature");
        }
        System.out.println("receive server finished");

        //send client Finished
        HandshakeMessage clientFinished = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTFINISHED);
        FileInputStream instream3 = new FileInputStream(handshakearguments.get("key"));
        HandshakeCrypto clientCrypto = new HandshakeCrypto(instream3.readAllBytes());
        Date timeNow = new Date();
        SimpleDateFormat clienttimestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        clientFinished.putParameter("TimeStamp",
                Base64.getEncoder().encodeToString(clientCrypto.encrypt(clienttimestamp.format(timeNow).toString().getBytes(StandardCharsets.UTF_8))));
        HandshakeDigest clientHandshakeDigest = new HandshakeDigest();
        clientHandshakeDigest.update(clientHello.getBytes());
        clientHandshakeDigest.update(clientsessionparameter.getBytes());
        clientFinished.putParameter("Signature",
                Base64.getEncoder().encodeToString(clientCrypto.encrypt(clientHandshakeDigest.digest())));
        clientFinished.send(handshakeSocket);
        System.out.println("send client Finished");
        System.out.println("Handshake close, start session");
    }

    public void doServerHandshake() throws Exception {

        //receive client hello
        HandshakeMessage clientHello = HandshakeMessage.recv(handshakeSocket);
        if (!clientHello.getType().equals(HandshakeMessage.MessageType.CLIENTHELLO)) {
            throw new Exception("Did not understand message");
        }
        FileInputStream instream1 = new FileInputStream(handshakearguments.get("cacert"));
        caCertificate = new HandshakeCertificate(instream1);
        byte[] bytearray = Base64.getDecoder().decode(clientHello.getParameter("Certificate"));
        clientCertificate = new HandshakeCertificate(bytearray);
        clientCertificate.verify(caCertificate);
        System.out.println("receive client hello from "+clientCertificate.getCN());

        //send server hello
        FileInputStream instream2 = new FileInputStream(handshakearguments.get("usercert"));
        serverCertificate = new HandshakeCertificate(instream2);
        HandshakeMessage serverHello = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
        serverHello.putParameter("Certificate",
                Base64.getEncoder().encodeToString(serverCertificate.getBytes()));
        serverHello.send(handshakeSocket);
        System.out.println("send server hello");

        //receive session key and IV
        HandshakeMessage sessionparameter = HandshakeMessage.recv(handshakeSocket);
        if (!sessionparameter.getType().equals(HandshakeMessage.MessageType.SESSION)) {
            throw new Exception("Did not understand message");
        }
        FileInputStream instream3 = new FileInputStream(handshakearguments.get("key"));
        HandshakeCrypto serverCrypto = new HandshakeCrypto(instream3.readAllBytes());
        SessionKey sessionKey = new SessionKey(serverCrypto.decrypt(Base64.getDecoder().decode(sessionparameter.getParameter("SessionKey"))));
        byte[] sessionIV = serverCrypto.decrypt(Base64.getDecoder().decode(sessionparameter.getParameter("SessionIV")));
        sessionCipher = new SessionCipher(sessionKey,sessionIV);
        System.out.println("receive session parameter");

        //send server Finished message
        HandshakeMessage serverFinished = new HandshakeMessage(HandshakeMessage.MessageType.SERVERFINISHED);
        Date timeNow = new Date();
        SimpleDateFormat servertimestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        serverFinished.putParameter("TimeStamp",
                Base64.getEncoder().encodeToString(serverCrypto.encrypt(servertimestamp.format(timeNow).toString().getBytes(StandardCharsets.UTF_8))));
        HandshakeDigest serverHandshakeDigest = new HandshakeDigest();
        serverHandshakeDigest.update(serverHello.getBytes());
        serverFinished.putParameter("Signature",
                Base64.getEncoder().encodeToString(serverCrypto.encrypt(serverHandshakeDigest.digest())));
        serverFinished.send(handshakeSocket);
        System.out.println("send server Finished");

        //receive client Finished
        HandshakeMessage clientFinished = HandshakeMessage.recv(handshakeSocket);
        if (!clientFinished.getType().equals(HandshakeMessage.MessageType.CLIENTFINISHED)) {
            throw new Exception("Did not understand message");
        }
        HandshakeCrypto clientCrypto = new HandshakeCrypto(clientCertificate);
        byte[] signature = clientCrypto.decrypt(Base64.getDecoder().decode(clientFinished.getParameter("Signature")));
        byte[] timestamprecv = clientCrypto.decrypt(Base64.getDecoder().decode(clientFinished.getParameter("TimeStamp")));

        SimpleDateFormat timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date timerecv = timestamp.parse(new String(timestamprecv, StandardCharsets.UTF_8));
        Date nowTime = new Date();
        long difference = (nowTime.getTime()-timerecv.getTime())/1000;
        if(difference>timelimit){
            throw new Exception("this message is old");
        }

        HandshakeDigest testHandshakeDigest = new HandshakeDigest();
        testHandshakeDigest.update(clientHello.getBytes());
        testHandshakeDigest.update(sessionparameter.getBytes());
        if(!HandshakeDigest.isEqual(testHandshakeDigest.digest(),signature)){
            throw new Exception("wrong signature");
        }
        System.out.println("receive client finished");
        System.out.println("Handshake close, start session");
    }
}
