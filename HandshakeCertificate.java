import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.*;

/*
 * HandshakeCertificate class represents X509 certificates exchanged
 * during initial handshake
 */
public class HandshakeCertificate {

    public X509Certificate certificate;

    /*
     * Constructor to create a certificate from data read on an input stream.
     * The data is DER-encoded, in binary or Base64 encoding (PEM format).
     */
    HandshakeCertificate(InputStream instream) throws CertificateException {

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        certificate = (X509Certificate)cf.generateCertificate(instream);
    }

    /*
     * Constructor to create a certificate from its encoded representation
     * given as a byte array
     */
    HandshakeCertificate(byte[] certbytes) throws CertificateException {

        InputStream instream = new ByteArrayInputStream(certbytes);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        certificate = (X509Certificate)cf.generateCertificate(instream);
    }

    /*
     * Return the encoded representation of certificate as a byte array
     */
    public byte[] getBytes() throws CertificateEncodingException {

        return certificate.getEncoded();
    }

    /*
     * Return the X509 certificate
     */
    public X509Certificate getCertificate() {

        return certificate;
    }

    /*
     * Cryptographically validate a certificate.
     * Throw relevant exception if validation fails.
     */
    public void verify(HandshakeCertificate cacert) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {

        X509Certificate cert = cacert.getCertificate();
        certificate.verify(cert.getPublicKey());
    }

    /*
     * Return CN (Common Name) of subject
     */
    public String getCN() {

        String name = certificate.getSubjectDN().getName();
        String[] str = name.split(",");
        return str[1].substring(str[1].indexOf("=")+1);
    }

    /*
     * return email address of subject
     */
    public String getEmail() {

        String name = certificate.getSubjectDN().getName();
        String[] str = name.split(",");
        return str[0].substring(str[0].indexOf("=")+1);
    }
}

