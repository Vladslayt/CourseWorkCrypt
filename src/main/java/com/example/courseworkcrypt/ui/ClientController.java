package com.example.courseworkcrypt.ui;

import javafx.scene.input.MouseEvent;
import javafx.stage.Stage;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.stage.FileChooser;

import java.io.File;
import java.io.IOException;

import com.example.courseworkcrypt.server.Client;


public class ClientController {

    public Button chooseFile;
    public Label file1Label;
    public Button sendFile;
    public Button chooseFile1;
    public Label file2Label;
    public Button downloadFile1;
    public Client client;
    public File selectedFile1;
    public File selectedFile2;

    @FXML
    private void initialize() {
        client = new Client(HelloController.encrMode, HelloController.serv);
        client.getSessionKey();
        client.getIV();
    }

    public void downloadFile_click(MouseEvent actionEvent) throws IOException {
        client.decryptFile(selectedFile2.getAbsolutePath(), selectedFile2.getName());
        file2Label.setText("Процесс завершён");
    }

    public void chooseFile1_click(MouseEvent actionEvent) {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Open Resource File");
        chooser.setInitialDirectory(new File("D:\\Программы\\IntelliJ IDEA Community Edition 2020.3.2\\CourseWorkCrypt\\src\\main\\resources\\server"));
        Stage stage = (Stage) chooseFile1.getScene().getWindow();
        selectedFile2 = chooser.showOpenDialog(stage);
        file2Label.setText(selectedFile2.getName());
    }

    public void sendFile_click(MouseEvent actionEvent) {
        client.encryptFile(selectedFile1);
        file1Label.setText("Процесс завешён");
    }

    public void chooseFile_click(MouseEvent actionEvent) {

        FileChooser chooser = new FileChooser();
        chooser.setTitle("Open Resource File");
        chooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("All Files", "*.*"),
                new FileChooser.ExtensionFilter("Text Files", "*.txt"),
                new FileChooser.ExtensionFilter("Image Files", "*.png", "*.jpg", "*.gif"),
                new FileChooser.ExtensionFilter("Audio Files", "*.wav", "*.mp3", "*.aac"));
        Stage stage = (Stage) chooseFile.getScene().getWindow();
        selectedFile1 = chooser.showOpenDialog(stage);
        file1Label.setText(selectedFile1.getAbsolutePath());
    }
}

