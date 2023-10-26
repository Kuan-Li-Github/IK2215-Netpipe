import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HandshakeDigest {

    private String HashAlgorithm = "SHA-256";
    private static MessageDigest messagedigest;
    /*
     * Constructor -- initialise a digest for SHA-256
     */
    public HandshakeDigest() throws NoSuchAlgorithmException {

        messagedigest = MessageDigest.getInstance(HashAlgorithm);
    }

    /*
     * Update digest with input data
     */
    public void update(byte[] input) {

        messagedigest.update(input);
    }

    /*
     * Compute final digest
     */
    public byte[] digest() {

        return messagedigest.digest();
    }

    public static boolean isEqual(byte[] digest1, byte[] digest2){

        return MessageDigest.isEqual(digest1,digest2);
    }
}
