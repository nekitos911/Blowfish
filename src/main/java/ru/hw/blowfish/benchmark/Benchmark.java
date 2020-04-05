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
    private static int ITERATIONS = 50;
    private static int BLOCKS = 1_000_000;

    public static void main(String[] args) throws IOException {
        val res = Arrays.stream(BlockCipherMode.values())
                .collect(Collectors.toMap(Enum::name, value -> Arrays.stream(EncipherMode.values())
                        .parallel()
                        .map(mode -> mode.name() + ": " + testEncipher(mode, value) + " ms")
                        .collect(Collectors.toList())));

        if (!Files.exists(Paths.get("benchmark/"))) {
            Files.createDirectory(Paths.get("benchmark/"));
        }

        Files.write(Paths.get("benchmark/benchmark.txt"), (LocalDateTime.now().toString() + "\n").getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        res.forEach((key, value) -> {
            try {
                Files.write(Paths.get("benchmark/benchmark.txt"), (key + ":" + "\n").getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                value.forEach(val -> {
                    try {
                        Files.write(Paths.get("benchmark/benchmark.txt"), (val + "\n").getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                });

            } catch (IOException e) {
                e.printStackTrace();
            }

        });
    }

    @SneakyThrows
    private static long testEncipher(EncipherMode mode, BlockCipherMode blockCipherMode) {
        val pwd = RandomStringUtils.randomAscii(4, 56);
        var bf = new Blowfish(pwd);
        val inputData = blockCipherMode != BlockCipherMode.DECIPHER ?
                RandomStringUtils.randomAscii(BLOCKS * Utils.BLOCK_SIZE).getBytes()
                : bf.encipher(RandomStringUtils.randomAscii(BLOCKS * Utils.BLOCK_SIZE).getBytes(), mode);

        var begin = Instant.now();
        byte[] res = null;
        for (int i = 0; i < ITERATIONS; i++) {
            res = blockCipherMode != BlockCipherMode.DECIPHER
                    ? bf.encipher(inputData, mode)
                    : bf.decipher(inputData);
        }
        val duration = Duration.between(begin, Instant.now()).abs().toMillis() / ITERATIONS;
        System.out.println(res);
        return duration;
    }
}
