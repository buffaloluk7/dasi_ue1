package crypto;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class KeyStorage
{
	public static void writePrivateKey(String filename, PrivateKey privateKey, DES DES ) throws AESException, IOException
	{
		byte[] encryptedKey = DES.encrypt(privateKey.getEncoded());
		Files.write(new File(filename).toPath(), encryptedKey, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
	}

	public static PrivateKey readPrivateKey(String filename, DES DES ) throws IOException, AESException, NoSuchAlgorithmException, InvalidKeySpecException
	{
		byte[] encryptedKey = Files.readAllBytes(new File(filename).toPath());
		byte[] decryptedKey = DES.decrypt(encryptedKey);

		return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decryptedKey));
	}
}
