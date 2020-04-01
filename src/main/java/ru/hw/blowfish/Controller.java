package ru.hw.blowfish;

import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import lombok.SneakyThrows;
import lombok.val;

import java.io.*;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

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
    private List<File> files;
    private static String IV = "12345678";
    private static final String ARCHIVE_NAME = "Encrypted.zip";
    private boolean isEncrypted;

    public void openFileButton() {
        FileChooser fileChooser = new FileChooser();
        files = fileChooser.showOpenMultipleDialog(null);
        folderPathLabel.setText("");
        Optional.ofNullable(files)
                .ifPresentOrElse(fNames -> fNames.forEach(file -> filePathLabel.appendText(file.getName() + "\n")),
                        () -> filePathLabel.setText("Select your files!!!"));
    }

    public void openFolderButton() {
        DirectoryChooser directoryChooser = new DirectoryChooser();
        File folderName = directoryChooser.showDialog(null);
        files = new LinkedList<>();
        files.add(folderName.getAbsoluteFile());
        filePathLabel.setText("");
        Optional.ofNullable(files.get(0))
                .ifPresentOrElse(f -> folderPathLabel.setText(f.getAbsolutePath() + File.separator),
                        () -> folderPathLabel.setText("Select your folder!!!"));
    }

    @SneakyThrows
    public void encipher() {
        isEncrypted = true;
        val bf = new Blowfish(secretKeyLabel.getCharacters().toString());
        try(val reader = new BufferedReader(
                new InputStreamReader(new FileInputStream(files.get(0).getPath()), "Cp1251"))) {

            val data = bf.encipher(reader.lines().collect(Collectors.joining("\n")));

            val dec = bf.decipher(data);
        }

        try(val writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream("encrypted.bin"), "Cp1251")
        )) {}

    }

    @SneakyThrows
    public void decipher() {
//        if(!isEncrypted)
//            bf = new Blowfish(secretKeyLabel.getCharacters().toString());
        FileInputStream fi = new FileInputStream(files.get(0).getPath());
        FileOutputStream fo = new FileOutputStream("encrypted.txt");
        InputStreamReader is = new InputStreamReader(fi,"Cp1251");
        OutputStreamWriter os = new OutputStreamWriter(fo,"Cp1251");
        String data = "";
        //bf.decrypt(data);
        System.out.println(data);
    }
}
