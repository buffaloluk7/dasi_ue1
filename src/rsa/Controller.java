package rsa;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.TextArea;
import sun.misc.BASE64Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public class Controller {
	@FXML private TextArea taPublicKey;
	@FXML private TextArea taPrivateKey;
	@FXML private TextArea taMessage;
	@FXML private TextArea taResult;
	@FXML private Button btnEncodeMessage;
	@FXML private Button btnDecodeMessage;

	RSA rsa = new RSA();

	@FXML
	protected void btnGenerateKeys(ActionEvent event) {
		try {
			rsa.initialize();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}

		KeyPair keys = rsa.getKeypair();

		String publicKey = new BASE64Encoder().encode(keys.getPublic().getEncoded());
		String privateKey = new BASE64Encoder().encode(keys.getPrivate().getEncoded());

		taPublicKey.setText(publicKey);
		taPrivateKey.setText(privateKey);

		btnEncodeMessage.setDisable(false);
		btnDecodeMessage.setDisable(false);
	}

	@FXML
	protected void btnEncodeMessageAction(ActionEvent event) {
		try {
			taResult.setText(rsa.encrypt(taMessage.getText()));
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		}
	}

	@FXML
	protected void btnDecodeMessageAction(ActionEvent event) {
		try {
			taResult.setText(rsa.decrypt(taMessage.getText()));
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		}
	}
}
