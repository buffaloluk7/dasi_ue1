package controller;

import crypto.*;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import sun.util.logging.resources.logging_es;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class Controller {
	@FXML
	private TextArea taMessage;
	@FXML
	private TextArea taResult;
	@FXML
	private TextArea taLog;
	@FXML
	private TextField tfPassword;

	private RSA rsa;

	@FXML
	protected void btnEncryptMessageAction(ActionEvent event) {
		if (rsa == null) {
			log("Generate a key pair first or import an existing one!");
			return;
		}

		if (taMessage.getText().isEmpty() || taMessage.getText().length() > 190) {
			log("Text empty or too long!");
			return;
		}

		try {
			taResult.setText(rsa.encrypt(taMessage.getText()));
		} catch (RSAException e) {
			logException(e.getMessage());
			return;
		}

		log("Text encrypted!");
	}

	@FXML
	protected void btnDecryptMessageAction(ActionEvent event) {
		if (rsa == null) {
			log("Generate a key pair first or import an existing one!");
			return;
		}

		if (taMessage.getText().isEmpty()) {
			log("Text empty!");
			return;
		}

		try {
			taResult.setText(rsa.decrypt(taMessage.getText()));
		} catch (RSAException | IllegalArgumentException e) {
			logException(e.getMessage());
			return;
		}

		log("Text decrypted!");
	}

	@FXML
	protected void btnGenerateKeys(ActionEvent event) {
		try {
			rsa = RSA.newInstance();
		} catch (RSAException e) {
			logException(e.getMessage());
			return;
		}

		log("New key pair generated");
	}

	@FXML
	protected void btnExportKeys(ActionEvent event) {
		if (rsa == null) {
			log("Generate a key pair first or import an existing one!");
			return;
		}

		if (tfPassword.getText().isEmpty() || tfPassword.getText().length() < 8) {
			log("Password empty or too short (minimum 8 chars)!");
			return;
		}

		try {
			KeyStorage.writePrivateKey("private.key", rsa.getKeyPair().getPrivate(), DES.newInstance(tfPassword.getText()));
			Files.write(new File("public.key").toPath(), rsa.getKeyPair().getPublic().getEncoded(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
		} catch (DESException | IOException | KeyStorageException e) {
			logException(e.getMessage());
			return;
		}

		log("Keys exported!");
	}

	@FXML
	protected void btnImportKeys(ActionEvent event) {
		if (tfPassword.getText().isEmpty() || tfPassword.getText().length() < 8) {
			log("Password empty or too short (minimum 8 chars)!");
			return;
		}

		try {
			PrivateKey privateKey = KeyStorage.readPrivateKey("private.key", DES.newInstance(tfPassword.getText()));

			PublicKey publicKey = KeyFactory
					.getInstance("RSA")
					.generatePublic(new X509EncodedKeySpec(Files.readAllBytes(new File("public.key").toPath())));

			KeyPair keyPair = new KeyPair(publicKey, privateKey);

			rsa = RSA.newInstance(keyPair);
		} catch (RSAException | InvalidKeySpecException | NoSuchAlgorithmException | IOException | KeyStorageException | DESException e) {
			logException(e.getMessage());
			return;
		}


		log("Keys imported");
	}

	@FXML
	protected void exitApplication(ActionEvent event) {
		System.exit(0);
	}

	private void log(String text) {
		taLog.appendText(text + "\n");
	}

	private void logException(String message) {
		String errorMessageOnly = message.substring(message.lastIndexOf(":") + 1, message.length());
		log(errorMessageOnly.trim());
	}
}