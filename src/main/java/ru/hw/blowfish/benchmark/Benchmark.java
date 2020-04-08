package ru.hw.blowfish.benchmark;

import lombok.SneakyThrows;
import lombok.val;
import org.apache.commons.lang3.RandomStringUtils;
import ru.hw.blowfish.Blowfish;
import ru.hw.blowfish.Utils;
import ru.hw.blowfish.enums.BlockCipherMode;
import ru.hw.blowfish.enums.EncipherMode;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.stream.Collectors;

public class Benchmark {
    private static int ITERATIONS = 10;
    private static int BLOCKS = 1_000_000;
    private static final String FOLDER = "benchmarks/";
    private static final String FILE = FOLDER + "benchmark.txt";

    public static void main(String[] args) throws IOException {
        val res = Arrays.stream(BlockCipherMode.values())
                .collect(Collectors.toMap(Enum::name, value -> Arrays.stream(EncipherMode.values())
                        .parallel()
                        .map(mode -> mode.name() + ": " + testEncipher(mode, value) + " ms")
                        .collect(Collectors.toList())));

        if (!Files.exists(Paths.get(FOLDER))) {
            Files.createDirectory(Paths.get(FOLDER));
        }

        Files.write(Paths.get(FILE), ("=".repeat(50) + "\n").getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        Files.write(Paths.get(FILE), (LocalDateTime.now().toString() + "\n").getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        Files.write(Paths.get(FILE), ("number of blocks: " + BLOCKS + "\n").getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        Files.write(Paths.get(FILE), ("iterations: " + ITERATIONS + "\n").getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);

        res.forEach((key, value) -> {
            try {
                Files.write(Paths.get(FILE), (key + ":" + "\n").getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                value.forEach(val -> {
                    try {
                        Files.write(Paths.get(FILE), (val + "\n").getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                });

            } catch (IOException e) {
                e.printStackTrace();
            }

        });

        Files.write(Paths.get(FILE), ("-".repeat(50) + "\n").getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }

    @SneakyThrows
    private static long testEncipher(EncipherMode mode, BlockCipherMode blockCipherMode) {
        val pwd = RandomStringUtils.randomAscii(4, 56);
        var bf = new Blowfish(pwd);
        val inputData = switch (blockCipherMode) {
            case ENCIPHER -> RandomStringUtils.randomAscii(BLOCKS * Utils.BLOCK_SIZE).getBytes();
            case DECIPHER -> bf.encipher(RandomStringUtils.randomAscii(BLOCKS * Utils.BLOCK_SIZE).getBytes(), mode);
        };

        byte[] res = null;
        var begin = Instant.now();
        for (int i = 0; i < ITERATIONS; i++) {
            res = switch(blockCipherMode) {
                case ENCIPHER -> bf.encipher(inputData, mode);
                case DECIPHER -> bf.decipher(inputData);
            };
        }
        val duration = Duration.between(begin, Instant.now()).abs().toMillis() / ITERATIONS;
        System.out.println(res);
        return duration;
    }
}
