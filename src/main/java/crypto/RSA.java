package crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Base64;

public class RSA
{
	PrivateKey privateKey;
	PublicKey  publicKey;
	Cipher     cipher;

	private RSA( Cipher cipher )
	{
		this.cipher = cipher;
	}

	public static RSA newInstance() throws NoSuchAlgorithmException, NoSuchPaddingException
	{
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

		RSA rsa = new RSA(cipher);

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);

		KeyPair keypair = keyPairGenerator.generateKeyPair();

		rsa.privateKey = keypair.getPrivate();
		rsa.publicKey = keypair.getPublic();

		return rsa;
	}

	public static RSA newInstance(KeyPair keypair) throws NoSuchPaddingException, NoSuchAlgorithmException
	{
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

		RSA rsa = new RSA(cipher);
		rsa.publicKey = keypair.getPublic();
		rsa.privateKey = keypair.getPrivate();

		return rsa;
	}

	public KeyPair getKeyPair()
	{
		return new KeyPair(this.publicKey, this.privateKey);
	}

	public String encrypt( String plaintext ) throws UnsupportedEncodingException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException
	{
		byte[] plaintextBytes = plaintext.getBytes("UTF-8");
		byte[] encryptedBytes = this.encrypt(plaintextBytes);

		byte[] base64encoded = Base64.getEncoder().encode(encryptedBytes);

		return new String(base64encoded);
	}

	public String decrypt( String ciphertext ) throws UnsupportedEncodingException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException
	{
		byte[] ciphertextBytes = Base64.getDecoder().decode(ciphertext.getBytes("UTF-8"));
		byte[] decryptedBytes = this.decrypt(ciphertextBytes);
		return new String(decryptedBytes);
	}

	public byte[] encrypt( byte[] plaintext ) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException
	{
		cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);

		return cipher.doFinal(plaintext);
	}

	public byte[] decrypt( byte[] ciphertext ) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException
	{
		cipher.init(Cipher.DECRYPT_MODE, this.privateKey);

		return cipher.doFinal(ciphertext);
	}
}
