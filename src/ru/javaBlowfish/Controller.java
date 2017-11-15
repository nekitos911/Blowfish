package ru.javaBlowfish;

import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;

import java.io.File;
import java.io.IOException;
import java.util.LinkedList;

public class Controller {
    @FXML
    private TextArea filePathLabel;
    @FXML
    private Label folderPathLabel;
    @FXML
    private Button selectFileButton;
    @FXML
    private Button selectFolderButton;
    @FXML
    private TextField secretKeyLabel;
    @FXML
    private Label errorLabel;
    private java.util.List<File> fileNames;
    private static String IV = "12345678";
    private static final String ARCHIVE_NAME = "Encrypted.zip";

    public void openFileButton() throws IOException {
        FileChooser fileChooser = new FileChooser();
        fileNames = fileChooser.showOpenMultipleDialog(null);
        folderPathLabel.setText("");
        if(fileNames == null)
            filePathLabel.setText("Select your files!!!");
        else {
            for (File file : fileNames) {
                filePathLabel.appendText(file.getName() + "\n");
            }
        }
    }

    public void openFolderButton() {
        DirectoryChooser directoryChooser = new DirectoryChooser();
        File folderName = directoryChooser.showDialog(null);
        fileNames = new LinkedList<>();
        fileNames.add(folderName.getAbsoluteFile());
        filePathLabel.setText("");
        if(fileNames.get(0) == null)
            folderPathLabel.setText("Select your folder!!!");
        else
            folderPathLabel.setText(fileNames.get(0).getAbsolutePath() + File.separator);
    }

    public void encrypt() {}
    public void decrypt() {}
}
