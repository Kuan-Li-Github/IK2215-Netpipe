import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import java.security.SecureRandom;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

class SessionKey {

    private String EncryptAlgorithm = "AES";
    private SecretKey secretkey;

    /*
     * Constructor to create a secret key of a given length
     */
    public SessionKey(Integer length) throws NoSuchAlgorithmException{

        KeyGenerator KeyGen = KeyGenerator.getInstance(EncryptAlgorithm);
        SecureRandom random = new SecureRandom();
        KeyGen.init(length,random);
        secretkey = KeyGen.generateKey();
    }

    /*
     * Constructor to create a secret key from key material
     * given as a byte array
     */
    public SessionKey(byte[] keybytes) {

        secretkey = new SecretKeySpec(keybytes, EncryptAlgorithm);
    }

    /*
     * Return the secret key
     */
    public SecretKey getSecretKey() {

        return secretkey;
    }

    /*
     * Return the secret key encoded as a byte array
     */
    public byte[] getKeyBytes() {

        return secretkey.getEncoded();
    }
}