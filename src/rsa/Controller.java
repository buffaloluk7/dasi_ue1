package rsa;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.TextArea;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class Controller {
    @FXML private TextArea taPublicKey;
    @FXML private TextArea taPrivateKey;
    @FXML private TextArea taMessage;
    @FXML private TextArea taResult;
    @FXML private Button btnEncodeMessage;
    @FXML private Button btnDecodeMessage;

    private RSA rsa = new RSA();

    public Controller() {
        try {
            rsa.initialize();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    @FXML
    protected void btnGenerateKeys(ActionEvent event) throws NoSuchPaddingException, NoSuchAlgorithmException {
        rsa.initialize();

        String publicKey = Base64.getEncoder().encodeToString(rsa.getPublicKey().getEncoded());
        String privateKey = Base64.getEncoder().encodeToString(rsa.getPrivateKey().getEncoded());

        taPublicKey.setText(publicKey);
        taPrivateKey.setText(privateKey);
    }

    @FXML
    protected void btnEncryptMessageAction(ActionEvent event) throws UnsupportedEncodingException, InvalidKeySpecException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        if (taMessage.getText().isEmpty() || taPublicKey.getText().isEmpty() || taMessage.getText().length() > 190) {
            return;
        }

        rsa.setPublicKey(taPublicKey.getText());
        taResult.setText(rsa.encrypt(taMessage.getText()));
    }

    @FXML
    protected void btnDecryptMessageAction(ActionEvent event) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (taMessage.getText().isEmpty() || taPrivateKey.getText().isEmpty()) {
            return;
        }

        rsa.setPrivateKey(taPrivateKey.getText());
        taResult.setText(rsa.decrypt(taMessage.getText()));
    }

    @FXML
    protected void btnExportPublicKey(ActionEvent event) throws IOException {
        this.saveToFile("public.key", taPublicKey.getText());
        Runtime.getRuntime().exec("notepad.exe public.key");
    }

    @FXML
    protected void btnExportPrivateKey(ActionEvent event) throws IOException {
        this.saveToFile("private.key", taPrivateKey.getText());
        Runtime.getRuntime().exec("notepad.exe private.key");
    }

    @FXML
    protected void btnImportPublicKey(ActionEvent event) throws IOException {
        taPublicKey.setText(this.readFromFile("public.key", StandardCharsets.UTF_8));
    }

    @FXML
    protected void btnImportPrivateKey(ActionEvent event) throws IOException {
        taPrivateKey.setText(this.readFromFile("private.key", StandardCharsets.UTF_8));
    }

    @FXML
    protected void exitApplication(ActionEvent event) {
        System.exit(0);
    }

    private void saveToFile(String filename, String text) throws IOException {
        FileOutputStream out = new FileOutputStream(filename);
        out.write(text.getBytes("UTF-8"));
        out.close();
    }

    private String readFromFile(String filename, Charset encoding) throws IOException {
        byte[] encoded = Files.readAllBytes(Paths.get(filename));
        return encoding.decode(ByteBuffer.wrap(encoded)).toString();
    }
}