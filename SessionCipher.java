import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.Cipher;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;



public class SessionCipher {

    private String CipherAlgorithm = "AES/CTR/NoPadding";
    private IvParameterSpec iv;
    private SessionKey sessionkey;
    private Cipher encryptcipher;
    private Cipher decryptcipher;

    /*
     * Constructor to create a SessionCipher from a SessionKey. The IV is
     * created automatically.
     */
    public SessionCipher(SessionKey key) throws InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        sessionkey = key;
        byte[] ivbytes_random = new byte[16];
        new SecureRandom().nextBytes(ivbytes_random);
        iv = new IvParameterSpec(ivbytes_random);
        encryptcipher = getCipher(Cipher.ENCRYPT_MODE);
        decryptcipher = getCipher(Cipher.DECRYPT_MODE);
    }

    /*
     * Constructor to create a SessionCipher from a SessionKey and an IV,
     * given as a byte array.
     */
    public SessionCipher(SessionKey key, byte[] ivbytes) throws InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        sessionkey = key;
        iv = new IvParameterSpec(ivbytes);
        encryptcipher = getCipher(Cipher.ENCRYPT_MODE);
        decryptcipher = getCipher(Cipher.DECRYPT_MODE);
    }

    /*
     * Return the SessionKey
     */
    public SessionKey getSessionKey() {

        return sessionkey;
    }

    /*
     * Return the IV as a byte array
     */
    public byte[] getIVBytes() {

        return iv.getIV();
    }

    /*
     * Attach OutputStream to which encrypted data will be written.
     * Return result as a CipherOutputStream instance.
     */
    public CipherOutputStream openEncryptedOutputStream(OutputStream os) {

        return new CipherOutputStream(os,encryptcipher);
    }

    /*
     * Attach InputStream from which decrypted data will be read.
     * Return result as a CipherInputStream instance.
     */
    public CipherInputStream openDecryptedInputStream(InputStream inputstream) {

        return new CipherInputStream(inputstream,decryptcipher);
    }

    /*
     * Return Cipher based on the chosen mode
     */
    public Cipher getCipher(Integer Mode) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {

        Cipher cipher = Cipher.getInstance(CipherAlgorithm);
        cipher.init(Mode,sessionkey.getSecretKey(),iv);
        return cipher;
    }
}
