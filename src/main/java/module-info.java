module com.example.courseworkcrypt {
    requires javafx.controls;
    requires javafx.fxml;


    opens com.example.courseworkcrypt to javafx.fxml;
    exports com.example.courseworkcrypt;
    exports com.example.courseworkcrypt.ui;
    opens com.example.courseworkcrypt.ui to javafx.fxml;
}