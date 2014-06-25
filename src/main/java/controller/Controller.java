package controller;

import crypto.AESException;
import crypto.DES;
import crypto.KeyStorage;
import crypto.RSA;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class Controller {
	@FXML
	private TextArea  taMessage;
	@FXML
	private TextArea  taResult;
	@FXML
	private TextArea  taLog;
	@FXML
	private TextField tfPassword;

	private RSA rsa;

	public Controller() throws NoSuchPaddingException, NoSuchAlgorithmException
	{
		rsa = RSA.newInstance();
	}

	@FXML
	protected void btnEncryptMessageAction( ActionEvent event ) throws UnsupportedEncodingException, InvalidKeySpecException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException
	{
		if( taMessage.getText().isEmpty() || taMessage.getText().length() > 190 )
		{
			log("Text empty or too long!");
			return;
		}

		taResult.setText(rsa.encrypt(taMessage.getText()));

		log("Text encrypted!");
	}

	@FXML
	protected void btnDecryptMessageAction( ActionEvent event ) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (taMessage.getText().isEmpty()) {
	        log("Text empty!");
            return;
        }

        taResult.setText(rsa.decrypt(taMessage.getText()));

		log("Text decrypted!");
    }


	@FXML
	protected void btnExportKeys(ActionEvent event) throws IOException, AESException
	{
		if ( tfPassword.getText().isEmpty() || tfPassword.getText().length() < 8)
		{
			log("Password empty or too short (minimum 8 chars)!");
			return;
		}
		KeyStorage.writePrivateKey("private.key", rsa.getKeyPair().getPrivate(), DES.newInstance(tfPassword.getText()));
		Files.write(new File("public.key").toPath(), rsa.getKeyPair().getPublic().getEncoded(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

		log("Keys exported!");
	}

	@FXML
	protected void btnImportKeys(ActionEvent event) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, AESException
	{
		if ( tfPassword.getText().isEmpty() || tfPassword.getText().length() < 8)
		{
			log("Password empty or too short (minimum 8 chars)!");
			return;
		}

		PrivateKey privateKey = KeyStorage.readPrivateKey("private.key", DES.newInstance(tfPassword.getText()));

		PublicKey publicKey = KeyFactory
				.getInstance("RSA")
				.generatePublic(new X509EncodedKeySpec(Files.readAllBytes(new File("public.key").toPath())));

		KeyPair keyPair = new KeyPair(publicKey, privateKey);

		rsa = RSA.newInstance(keyPair);

		log("Keys imported");
	}

    @FXML
    protected void exitApplication(ActionEvent event) {
        System.exit(0);
    }

	private void log(String text) {
		taLog.setText(taLog.getText().concat("\n").concat(text));
	}
}