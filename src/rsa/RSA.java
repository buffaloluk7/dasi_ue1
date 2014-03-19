package rsa;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class RSA {
    private KeyPair keypair;
    private Cipher rsa;

    public void initialize() throws NoSuchAlgorithmException, NoSuchPaddingException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        keypair = keyPairGenerator.generateKeyPair();
        rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    }

    public KeyPair getKeypair() {
        return keypair;
    }

    public void setKeypair(KeyPair keypair) {
        this.keypair = keypair;
    }

    public String encrypt(String plaintext) throws InvalidKeyException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException {
        rsa.init(Cipher.ENCRYPT_MODE, keypair.getPublic());

        byte[] encrypted = rsa.doFinal(plaintext.getBytes("UTF-8"));

        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String decrypt(String cipherText) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        rsa.init(Cipher.DECRYPT_MODE, keypair.getPrivate());

        byte[] decrypted = rsa.doFinal(Base64.getDecoder().decode(cipherText));

        return new String(decrypted);
    }
}
