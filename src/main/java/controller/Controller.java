package controller;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.TextArea;
import rsa.RSA;
import rsa.SecureKeyManager;

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
import java.security.spec.PKCS8EncodedKeySpec;

public class Controller {
	@FXML
	private TextArea taMessage;
	@FXML
	private TextArea taResult;

	private RSA rsa;

	public Controller() throws NoSuchPaddingException, NoSuchAlgorithmException
	{
		rsa = RSA.newInstance();
	}

	@FXML
	protected void btnEncryptMessageAction( ActionEvent event) throws UnsupportedEncodingException, InvalidKeySpecException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        if (taMessage.getText().isEmpty() || taMessage.getText().length() > 190) {
            return;
        }

        taResult.setText(rsa.encrypt(taMessage.getText()));
    }

    @FXML
    protected void btnDecryptMessageAction(ActionEvent event) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (taMessage.getText().isEmpty()) {
            return;
        }

        taResult.setText(rsa.decrypt(taMessage.getText()));
    }


	@FXML
	protected void btnExportKeys(ActionEvent event) throws IOException
	{
		SecureKeyManager.save(manager -> manager.encryptedWith("test1234")
		                                        .save(rsa.getKeyPair().getPrivate())
		                                        .in("private.key"));

		Files.write(new File("public.key").toPath(), rsa.getKeyPair().getPublic().getEncoded(), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
	}

	@FXML
	protected void btnImportKeys(ActionEvent event) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException
	{
		PrivateKey privateKey = SecureKeyManager.load(manager -> manager.from("private.key").encryptedWith("test1234").load());

		PublicKey publicKey = KeyFactory
				.getInstance("RSA")
				.generatePublic(new PKCS8EncodedKeySpec(Files.readAllBytes(new File("public.key").toPath())));

		KeyPair keyPair = new KeyPair(publicKey, privateKey);

		rsa = RSA.newInstance(keyPair);
	}

    @FXML
    protected void exitApplication(ActionEvent event) {
        System.exit(0);
    }
}