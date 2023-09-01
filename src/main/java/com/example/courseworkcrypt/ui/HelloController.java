package com.example.courseworkcrypt.ui;

import com.example.courseworkcrypt.HelloApplication;
import com.example.courseworkcrypt.algorithms.RC6;
import javafx.fxml.FXML;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ChoiceBox;
import javafx.stage.Stage;
import com.example.courseworkcrypt.server.Server;
import java.io.IOException;
import java.util.Objects;

import static com.example.courseworkcrypt.algorithms.RC6.encryptionMode;

public class HelloController {

    public Button helloButton;
    public static Server serv;
    public static RC6.encryptionMode encrMode;
    ObservableList<String> em = FXCollections.observableArrayList("ECB", "CBC", "CFB", "OFB", "CTR", "RD", "RD+H");
    public ChoiceBox<String> EncModesCB;
    @FXML
    public void initialize(){
        EncModesCB.setItems(em);
        EncModesCB.setValue("ECB");
    }
    @FXML
    protected void onHelloButtonClick() throws RuntimeException {
        serv = new Server();
        if (Objects.equals(EncModesCB.getValue(), "ECB"))
            encrMode = encryptionMode.ECB;
        if (Objects.equals(EncModesCB.getValue(), "CBC"))
            encrMode = encryptionMode.CBC;
        if (Objects.equals(EncModesCB.getValue(), "CFB"))
            encrMode = encryptionMode.CFB;
        if (Objects.equals(EncModesCB.getValue(), "OFB"))
            encrMode = encryptionMode.OFB;
        if (Objects.equals(EncModesCB.getValue(), "CTR"))
            encrMode = encryptionMode.CTR;
        if (Objects.equals(EncModesCB.getValue(), "RD"))
            encrMode = encryptionMode.RD;
        if (Objects.equals(EncModesCB.getValue(), "RD+H"))
            encrMode = encryptionMode.RD;

        Stage stage = (Stage) helloButton.getScene().getWindow();
        FXMLLoader fxmlLoader = new FXMLLoader(HelloApplication.class.getResource("hello-view.fxml"));
        try {
            Scene scene = new Scene(fxmlLoader.load());
            stage.setTitle("Курсовая");
            stage.setScene(scene);
            stage.show();
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }
}
