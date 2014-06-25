package crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Base64;

public class RSA {
	PrivateKey privateKey;
	PublicKey publicKey;
	Cipher cipher;

	private RSA(Cipher cipher) {
		this.cipher = cipher;
	}

	public static RSA newInstance() throws RSAException {
		KeyPairGenerator keyPairGenerator;

		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
		} catch (NoSuchAlgorithmException e) {
			throw new RSAException(e);
		}

		KeyPair keypair = keyPairGenerator.generateKeyPair();

		return RSA.newInstance(keypair);
	}

	public static RSA newInstance(KeyPair keypair) throws RSAException {
		Cipher cipher;

		try {
			cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new RSAException(e);
		}

		RSA rsa = new RSA(cipher);
		rsa.publicKey = keypair.getPublic();
		rsa.privateKey = keypair.getPrivate();

		return rsa;
	}

	public KeyPair getKeyPair() {
		return new KeyPair(this.publicKey, this.privateKey);
	}

	public String encrypt(String plaintext) throws RSAException {
		byte[] plaintextBytes;
		byte[] encryptedBytes;

		try {
			plaintextBytes = plaintext.getBytes("UTF-8");
			encryptedBytes = this.encrypt(plaintextBytes);
		} catch (UnsupportedEncodingException | RSAException e) {
			throw new RSAException(e);
		}

		byte[] base64encoded = Base64.getEncoder().encode(encryptedBytes);

		return new String(base64encoded);
	}

	public String decrypt(String cipherText) throws RSAException {
		byte[] cipherTextBytes;
		byte[] decryptedBytes;

		try {
			cipherTextBytes = Base64.getDecoder().decode(cipherText.getBytes("UTF-8"));
			decryptedBytes = this.decrypt(cipherTextBytes);
		} catch (UnsupportedEncodingException | RSAException e) {
			throw new RSAException(e);
		}

		return new String(decryptedBytes);
	}

	public byte[] encrypt(byte[] plaintext) throws RSAException {
		try {
			cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);

			return cipher.doFinal(plaintext);
		} catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
			throw new RSAException(e);
		}
	}

	public byte[] decrypt(byte[] cipherText) throws RSAException {
		try {
			cipher.init(Cipher.DECRYPT_MODE, this.privateKey);

			return cipher.doFinal(cipherText);
		} catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
			throw new RSAException(e);
		}
	}
}
