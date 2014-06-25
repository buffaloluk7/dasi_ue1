package crypto;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class DES {
	private final SecretKey secretKey;
	private final Cipher cipher;

	private DES(SecretKey secretKey, Cipher cipher) {
		this.secretKey = secretKey;
		this.cipher = cipher;
	}

	public static DES newInstance(String password) throws DESException {
		Cipher cipher;
		SecretKey secretKey;

		try {
			DESKeySpec dks = new DESKeySpec(password.getBytes("UTF-8"));
			SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
			secretKey = skf.generateSecret(dks);
			cipher = Cipher.getInstance("DES");
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | UnsupportedEncodingException e) {
			throw new DESException(e);
		}

		return new DES(secretKey, cipher);
	}

	public byte[] encrypt(byte[] plainText) throws DESException {
		try {
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);

			return cipher.doFinal(plainText);
		} catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
			throw new DESException(e);
		}
	}

	public byte[] decrypt(byte[] cipherText) throws DESException {
		try {
			cipher.init(Cipher.DECRYPT_MODE, secretKey);

			return cipher.doFinal(cipherText);
		} catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
			throw new DESException(e);
		}
	}
}

