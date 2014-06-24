package rsa;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.function.Consumer;
import java.util.function.Function;

public class SecureKeyManager
{
	private static final String PBE_WITH_SHA1_AND_DESEDE = "PBEWithSHA1AndDESede";

	private SecretKey               secretKey;
	private EncryptedPrivateKeyInfo encryptedPrivateKeyInfo;
	private PBEParameterSpec        pbeParamSpec;

	private SecureKeyManager(){ }

	public static void save( Consumer<SecureKeyManager> consumer )
	{
		SecureKeyManager keyManager = new SecureKeyManager();
		consumer.accept(keyManager);
	}

	public SecureKeyManager save( PrivateKey privateKey )
	{
		try
		{
			Cipher cipher = Cipher.getInstance(PBE_WITH_SHA1_AND_DESEDE);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, pbeParamSpec);

			byte[] encryptedPrivateKey = cipher.doFinal(privateKey.getEncoded());
			AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance(PBE_WITH_SHA1_AND_DESEDE);

			algorithmParameters.init(pbeParamSpec);
			encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(algorithmParameters, encryptedPrivateKey);
		}
		catch(NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | InvalidParameterSpecException e )
		{
			throw new KeyManagerException(e);
		}

		return this;
	}

	public PrivateKey load ()
	{
		try
		{
			Cipher pbeCipher = Cipher.getInstance(PBE_WITH_SHA1_AND_DESEDE);
			pbeCipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParamSpec);

			byte[] decrypted = pbeCipher.doFinal(encryptedPrivateKeyInfo.getEncryptedData());
			return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decrypted));
		}
		catch( NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException | InvalidKeyException | InvalidAlgorithmParameterException e )
		{
			throw new KeyManagerException(e);
		}
	}

	public static PrivateKey load( Function<SecureKeyManager, PrivateKey> function)
	{
		SecureKeyManager secureKeyManager = new SecureKeyManager();

		return function.apply(secureKeyManager);
	}

	public SecureKeyManager in( String path )
	{
		try( FileOutputStream outputStream = new FileOutputStream(path) )
		{
			byte[] encryptedPkcs8 = encryptedPrivateKeyInfo.getEncoded();
			outputStream.write(encryptedPkcs8);
		}
		catch( IOException e )
		{
			throw new KeyManagerException(e);
		}

		return this;
	}

	public SecureKeyManager from( String path )
	{
		try
		{
			byte[] encryptedPkcs8 = Files.readAllBytes(new File(path).toPath());
			encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(encryptedPkcs8);
		}
		catch( IOException e )
		{
			throw new KeyManagerException(e);
		}

		return this;
	}

	public SecureKeyManager encryptedWith( String password )
	{
		int count = 20;// hash iteration count
		SecureRandom random = new SecureRandom();
		byte[] salt = new byte[8];
		random.nextBytes(salt);

		// Create PBE parameter set
		pbeParamSpec = new PBEParameterSpec(salt, count);

		PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());

		try
		{
			SecretKeyFactory keyFac = SecretKeyFactory.getInstance(PBE_WITH_SHA1_AND_DESEDE);
			secretKey = keyFac.generateSecret(pbeKeySpec);
		}
		catch( NoSuchAlgorithmException | InvalidKeySpecException e )
		{
			throw new KeyManagerException(e);
		}

		return this;
	}

	public class KeyManagerException extends RuntimeException
	{
		public KeyManagerException( Throwable cause )
		{
			super(cause);
		}
	}
}
