package rsa;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
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

	public void saveToKeystore(String keystorePath, String password) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidParameterSpecException
	{
		FileInputStream inputStream = new FileInputStream(keystorePath);


	}

	public KeyPair getKeyPair()
	{
		return new KeyPair(this.publicKey, this.privateKey);
	}

	public String encrypt( String plaintext ) throws InvalidKeyException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException
	{
		cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);

		byte[] encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"));

		return Base64.getEncoder().encodeToString(encrypted);
	}

	public String decrypt( String cipherText ) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException
	{
		cipher.init(Cipher.DECRYPT_MODE, this.privateKey);

		byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(cipherText));

		return new String(decrypted);
	}
}
