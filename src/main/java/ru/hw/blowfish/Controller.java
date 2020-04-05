package ru.hw.blowfish;

import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import lombok.SneakyThrows;
import lombok.val;
import org.apache.commons.lang3.ArrayUtils;
import ru.hw.blowfish.enums.EncipherMode;

import java.io.*;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.*;
import java.util.stream.Collectors;

public class Controller implements Initializable {
    @FXML
    private TextArea filePathLabel;
    @FXML
    private Label folderPathLabel;
    @FXML
    private Button selectFileButton;
    @FXML
    private Button selectFolderButton;
    @FXML
    private Button decipherBtn;
    @FXML
    private Button encipherBtn;
    @FXML
    private TextField secretKeyLabel;
    @FXML
    private Label errorLabel;
    @FXML
    private ComboBox<String> encipherModeCB;
    private List<File> files;
    private static final String ARCHIVE_NAME = "Encrypted.bin";
    private static final String DECRYPTED_FOLDER = "decrypted/";
    private boolean isEncrypted;

    public void openFileButton() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setInitialDirectory(new File("."));
        files = fileChooser.showOpenMultipleDialog(null);
        folderPathLabel.setText("");
        Optional.ofNullable(files)
                .ifPresentOrElse(fNames -> fNames.forEach(file -> filePathLabel.appendText(file.getName() + "\n")),
                        () -> filePathLabel.setText("Select your files!!!"));

        encipherBtn.setDisable(false);
        decipherBtn.setDisable(false);

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

        encipherBtn.setDisable(false);
        decipherBtn.setDisable(false);
    }

    @SneakyThrows
    public void encipher() {
        val mode = EncipherMode.valueOf(encipherModeCB.getValue());
        isEncrypted = true;
        val bf = new Blowfish(secretKeyLabel.getCharacters().toString());

        byte[] encipheredData = bf.encipher(
                ArrayUtils.toPrimitive(files.stream()
                .map(File::toPath)
                .map(file -> {
                    var name = file.getFileName().toString().getBytes();
                    val size = file.toFile().length();
                    byte[] data = new byte[0];
                    try {
                        data = ArrayUtils.addAll(
                                ByteBuffer.allocate(8).putLong(size).array(),
                                ArrayUtils.addAll(
                                        ArrayUtils.addAll(
                                                ByteBuffer.allocate(8).putLong(name.length).array(),
                                                name),
                                        Files.readAllBytes(file)
                                )
                        );
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    return data;
                }).flatMap(bytes -> Arrays.stream(ArrayUtils.toObject(bytes)))
                .toArray(Byte[]::new)), mode);

        val name = UUID.randomUUID() + "_" + ARCHIVE_NAME;
        Files.write(Paths.get(name), encipheredData, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);

        filePathLabel.clear();
        encipherBtn.setDisable(true);
        decipherBtn.setDisable(true);
    }

    @SneakyThrows
    public void decipher() {
        val bf = new Blowfish(secretKeyLabel.getCharacters().toString());
        val deciphered = bf.decipher(Files.readAllBytes(files.get(0).toPath()));
        try (val reader = new ByteArrayInputStream(deciphered)) {
            while (reader.available() > 0) {
                val fileSize = ByteBuffer.wrap(reader.readNBytes(8)).getLong();
                val fileNameSize = ByteBuffer.wrap(reader.readNBytes(8)).getLong();
                val fileName = new String(reader.readNBytes((int)fileNameSize));
                val file = reader.readNBytes((int)fileSize);

                Files.write(Paths.get(DECRYPTED_FOLDER + fileName), file, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
            }
        }

        filePathLabel.clear();
        encipherBtn.setDisable(true);
        decipherBtn.setDisable(true);
    }

    @SneakyThrows
    @Override
    public void initialize(URL location, ResourceBundle resources) {
        if (!Files.exists(Paths.get(DECRYPTED_FOLDER))) Files.createDirectory(Paths.get(DECRYPTED_FOLDER));
        encipherModeCB.getItems().addAll(Arrays.stream(EncipherMode.values()).map(EncipherMode::name).collect(Collectors.toList()));

    }
}
