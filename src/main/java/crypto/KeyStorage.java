package crypto;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class KeyStorage {
	public static void writePrivateKey(String filename, PrivateKey privateKey, DES des) throws KeyStorageException {
		try {
			byte[] encryptedKey = des.encrypt(privateKey.getEncoded());
			Files.write(new File(filename).toPath(), encryptedKey, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
		} catch (DESException | IOException e) {
			throw new KeyStorageException(e);
		}
	}

	public static PrivateKey readPrivateKey(String filename, DES des) throws KeyStorageException {
		try {
			byte[] encryptedKey = Files.readAllBytes(new File(filename).toPath());
			byte[] decryptedKey = des.decrypt(encryptedKey);

			return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decryptedKey));
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException | DESException e) {
			throw new KeyStorageException(e);
		}
	}
}
