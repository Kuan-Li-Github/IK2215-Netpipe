import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class HandshakeCrypto {

	private static final String CipherAlgorithm = "RSA";
	private Cipher encryptcipher;
	private Cipher decryptcipher;
	private PublicKey publicKey;
	private PrivateKey privateKey;

	/*
	 * Constructor to create an instance for encryption/decryption with a public key.
	 * The public key is given as a X509 certificate.
	 */
	public HandshakeCrypto(HandshakeCertificate handshakeCertificate) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

		X509Certificate certificate = handshakeCertificate.getCertificate();
		publicKey = certificate.getPublicKey();
		encryptcipher = getCipher(Cipher.ENCRYPT_MODE,publicKey);
		decryptcipher = getCipher(Cipher.DECRYPT_MODE,publicKey);
	}

	/*
	 * Constructor to create an instance for encryption/decryption with a private key.
	 * The private key is given as a byte array in PKCS8/DER format.
	 */
	public HandshakeCrypto(byte[] keybytes) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException {

		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keybytes);
		KeyFactory keyFactory = KeyFactory.getInstance(CipherAlgorithm);
		privateKey = keyFactory.generatePrivate(keySpec);
		encryptcipher = getCipher(Cipher.ENCRYPT_MODE,privateKey);
		decryptcipher = getCipher(Cipher.DECRYPT_MODE,privateKey);
	}

	/*
	 * Decrypt byte array with the key, return result as a byte array
	 */
    public byte[] decrypt(byte[] ciphertext) throws IllegalBlockSizeException, BadPaddingException {

		return decryptcipher.doFinal(ciphertext);
    }

	/*
	 * Encrypt byte array with the key, return result as a byte array
	 */
    public byte [] encrypt(byte[] plaintext) throws IllegalBlockSizeException, BadPaddingException {

		return encryptcipher.doFinal(plaintext);
    }

	public Cipher getCipher(Integer Mode,Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

		Cipher cipher = Cipher.getInstance(CipherAlgorithm);
		cipher.init(Mode,key);
		return cipher;
	}
}
