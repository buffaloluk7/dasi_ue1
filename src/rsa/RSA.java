package rsa;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSA {
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private Cipher rsa;
    String algorithm = "RSA";

    public void initialize(int bitLength) throws NoSuchAlgorithmException, NoSuchPaddingException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        keyPairGenerator.initialize(bitLength);

        KeyPair keypair = keyPairGenerator.generateKeyPair();
        this.privateKey = keypair.getPrivate();
        this.publicKey = keypair.getPublic();

        this.rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    }

    public void initialize() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.initialize(2048);
    }

    public KeyPair getKeyPair() {
        return new KeyPair(this.publicKey, this.privateKey);
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }

    public void setPublicKey(String publicKey) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] key = Base64.getDecoder().decode(publicKey.getBytes("UTF-8"));

        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(key);

        this.publicKey = KeyFactory.getInstance(algorithm).generatePublic(publicKeySpec);
    }

    public void setPrivateKey(String privateKey) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] key = Base64.getDecoder().decode(privateKey.getBytes("UTF-8"));

        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(key);

        this.privateKey = KeyFactory.getInstance(algorithm).generatePrivate(privateKeySpec);
    }

    public void setKeypair(KeyPair keypair) {
        this.publicKey = keypair.getPublic();
        this.privateKey = keypair.getPrivate();
    }

    public String encrypt(String plaintext) throws InvalidKeyException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException {
        if (this.publicKey == null) {
            throw new InvalidKeyException();
        }

        rsa.init(Cipher.ENCRYPT_MODE, this.publicKey);

        byte[] encrypted = rsa.doFinal(plaintext.getBytes("UTF-8"));

        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String decrypt(String cipherText) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        if (this.privateKey == null) {
            throw new InvalidKeyException();
        }

        rsa.init(Cipher.DECRYPT_MODE, this.privateKey);

        byte[] decrypted = rsa.doFinal(Base64.getDecoder().decode(cipherText));

        return new String(decrypted);
    }
}
