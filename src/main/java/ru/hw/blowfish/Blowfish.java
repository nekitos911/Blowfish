package ru.hw.blowfish;

import com.google.common.collect.Lists;
import lombok.SneakyThrows;
import lombok.val;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import ru.hw.blowfish.enums.BlockCipherMode;
import ru.hw.blowfish.enums.EncipherMode;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static ru.hw.blowfish.Utils.*;
import static ru.hw.blowfish.enums.BlockCipherMode.ENCIPHER;

public class Blowfish {
    private long[] p = new long[N + 2];
    private long[][] s = new long[4][256];
    private byte[] byteIV;

    public Blowfish(String hexKey) {
        if (hexKey.length() > 56)
            throw new RuntimeException("key should be more less 56");
        else if (hexKey.length() < 4)
            throw new RuntimeException("key should be more than 3");

        setupKey(hexKey.getBytes());
    }

    private void setupKey(byte[] key) {
        System.arraycopy(RandomNumberTables.bf_P, 0, p, 0, N + 2);
        for (int i = 0; i < s.length; i++)
            System.arraycopy(RandomNumberTables.bf_S[i], 0, s[i], 0, s[i].length);

        val repeatedKey = Lists.partition(
                IntStream.range(0, (N + 2) * Integer.BYTES)
                        .mapToObj(i -> key[i % key.length])
                        .collect(Collectors.toList()),
                Integer.BYTES
        )
                .parallelStream()
                .map(lst -> lst.toArray(Byte[]::new))
                .map(ArrayUtils::toPrimitive)
                .map(arr -> ByteBuffer.wrap(arr).getInt())
                .map(Utils::unsignedInt)
                .toArray(Long[]::new);

        for (int i = 0; i < N + 2; i++) {
            p[i] = xor(unsignedInt(p[i]), repeatedKey[i]);
        }

        var pair = new ImmutablePair<>(0L, 0L);

        for (int i = 0; i < N + 2; i += 2) {
            pair = callCipher(pair.left, pair.right, ENCIPHER);
            p[i] = pair.left;
            p[i + 1] = pair.right;
        }

        for (var sBucket : s) {
            for (int k = 0; k < 256; k += 2) {
                pair = callCipher(pair.left, pair.right, ENCIPHER);
                sBucket[k] = pair.left;
                sBucket[k + 1] = pair.right;
            }
        }
    }

    private ImmutablePair<Long, Long> callCipher(long xl, long xr, BlockCipherMode mode) {
        switch (mode) {
            case ENCIPHER -> {
                xl = xor(xl, p[0]);

                for (int i = 1; i < ROUNDS; i += 2) {
                    xr = xor(xr, xor(F(xl), p[i]));
                    xl = xor(xl, xor(F(xr), p[i + 1]));
                }
                xr = xor(xr, p[N + 1]);
            }
            case DECIPHER -> {
                xl = xor(xl, p[N + 1]);

                for (int i = N; i > 0; i -= 2) {
                    xr = xor(xr, xor(F(xl), p[i]));
                    xl = xor(xl, xor(F(xr), p[i - 1]));
                }
                xr = xor(xr, p[0]);
            }
        }
        //Swap Xl and Xr
        return new ImmutablePair<>(xr, xl);
    }

    private byte[] ECBMode(List<byte[]> blocks, BlockCipherMode mode) {
        return ArrayUtils.toPrimitive(
                blocks.parallelStream()
                        .flatMap(block -> Arrays.stream(ArrayUtils.toObject(setBlock(block, mode))))
                        .toArray(Byte[]::new)
        );
    }

    private byte[] ECBEncipher(List<byte[]> blocks) {
        return ECBMode(blocks, BlockCipherMode.ENCIPHER);
    }

    private byte[] ECBDecipher(List<byte[]> blocks) {
        return ECBMode(blocks, BlockCipherMode.DECIPHER);
    }

    private byte[] CBCEncipher(List<byte[]> blocks) {
        val mode = BlockCipherMode.ENCIPHER;

        // проксорил с IV первый блок
        for (int i = 0; i < BLOCK_SIZE; i++) {
            blocks.get(0)[i] ^= byteIV[i];
        }

        // зашифровал первый блок и положил на выход
        blocks.set(0, setBlock(blocks.get(0), mode));

        // все остальные блоки
        for (int i = 1; i < blocks.size(); i++) {
            byte[] firstBlock = blocks.get(i - 1);
            byte[] secondBlock = blocks.get(i);

            // проксорил блоки (зашифрованный с открытым)
            for (int j = 0; j < BLOCK_SIZE; j++) {
                secondBlock[j] ^= firstBlock[j];
            }

            // зашифровал открытый блок и положил на выход
            blocks.set(i, setBlock(secondBlock, mode));
        }

        return ArrayUtils.toPrimitive(
                blocks
                        .parallelStream()
                        .flatMap(block -> Arrays.stream(ArrayUtils.toObject(block)))
                        .toArray(Byte[]::new)
        );
    }

    private byte[] CBCDecipher(List<byte[]> blocks) {
        val mode = BlockCipherMode.DECIPHER;

        // на выход все блоки, кроме первого
        for (int i = blocks.size() - 1; i >= 1; i--) {
            // последний блок
            byte[] lastBlock = blocks.get(i);
            // предпоследний блок
            byte[] prevBlock = blocks.get(i - 1);

            // расшифровал последний
            lastBlock = setBlock(lastBlock, mode);

            // заксорил с предпоследним
            for (int j = 0; j < BLOCK_SIZE; j++) {
                lastBlock[j] ^= prevBlock[j];
            }

            // положил на выход
            blocks.set(i, lastBlock);
        }

        // расшифровал первый блок
        blocks.set(0, setBlock(blocks.get(0), mode));

        // проксорил первый блок с IV и положил 1 блок на выход
        for (int i = 0; i < blocks.get(0).length; i++) {
            blocks.get(0)[i] ^= byteIV[i];
        }

        return ArrayUtils.toPrimitive(
                blocks
                        .parallelStream()
                        .flatMap(block -> Arrays.stream(ArrayUtils.toObject(block)))
                        .toArray(Byte[]::new)
        );
    }

    private byte[] OFBMode(List<byte[]> blocks) {
        var byteIVCopy = ArrayUtils.clone(byteIV);

        for (byte[] bytes : blocks) {
            // Шифруем/Дешифруем IV
            byteIVCopy = setBlock(byteIVCopy, BlockCipherMode.ENCIPHER);

            // проксорил блоки (зашифрованный IV с блоком)
            for (int j = 0; j < BLOCK_SIZE; j++) {
                bytes[j] ^= byteIVCopy[j];
            }
        }

        return ArrayUtils.toPrimitive(
                blocks
                        .parallelStream()
                        .flatMap(block -> Arrays.stream(ArrayUtils.toObject(block)))
                        .toArray(Byte[]::new)
        );
    }

    private byte[] PCBCEncipher(List<byte[]> blocks) {
        val mode = BlockCipherMode.ENCIPHER;
        val blocksCopy = blocks.stream().map(ArrayUtils::clone).collect(Collectors.toList());

        // проксорил с IV первый блок
        for (int i = 0; i < BLOCK_SIZE; i++) {
            blocks.get(0)[i] ^= byteIV[i];
        }

        // зашифровал первый блок и положил на выход
        blocks.set(0, setBlock(blocks.get(0), mode));

        // все остальные блоки
        for (int i = 1; i < blocks.size(); i++) {
            for (int j = 0; j < BLOCK_SIZE; j++) {
                blocksCopy.get(i - 1)[j] ^= blocks.get(i - 1)[j];
            }
            byte[] firstBlock = blocksCopy.get(i - 1);
            byte[] secondBlock = blocks.get(i);

            // проксорил блоки (зашифрованный с открытым)
            for (int j = 0; j < BLOCK_SIZE; j++) {
                secondBlock[j] ^= firstBlock[j];
            }

            // зашифровал открытый блок и положил на выход
            blocks.set(i, setBlock(secondBlock, mode));
        }

        return ArrayUtils.toPrimitive(
                blocks
                        .parallelStream()
                        .flatMap(block -> Arrays.stream(ArrayUtils.toObject(block)))
                        .toArray(Byte[]::new)
        );
    }

    private byte[] PCBCDecipher(List<byte[]> blocks) {
        val mode = BlockCipherMode.DECIPHER;
        val blocksCopy = blocks.stream().map(ArrayUtils::clone).collect(Collectors.toList());

        // расшифровал первый блок и положил на выход
        blocks.set(0, setBlock(blocks.get(0), mode));

        // проксорил с IV первый блок
        for (int i = 0; i < blocks.get(0).length; i++) {
            blocks.get(0)[i] ^= byteIV[i];
        }

        // все остальные блоки
        for (int i = 1; i < blocks.size(); i++) {
            for (int j = 0; j < BLOCK_SIZE; j++) {
                blocksCopy.get(i - 1)[j] ^= blocks.get(i - 1)[j];
            }
            byte[] firstBlock = blocksCopy.get(i - 1);
            var secondBlock = setBlock(blocks.get(i), BlockCipherMode.DECIPHER);

            for (int j = 0; j < BLOCK_SIZE; j++) {
                secondBlock[j] ^= firstBlock[j];
            }

            blocks.set(i, secondBlock);
        }

        return ArrayUtils.toPrimitive(
                blocks
                        .parallelStream()
                        .flatMap(block -> Arrays.stream(ArrayUtils.toObject(block)))
                        .toArray(Byte[]::new)
        );
    }

    @SneakyThrows
    public byte[] encipher(byte[] data, EncipherMode encipherMode) {
        // Set random IV
        byteIV = SecureRandom.getInstanceStrong().generateSeed(BLOCK_SIZE);
        val realLength = data.length;
        val padding = (BLOCK_SIZE - data.length % BLOCK_SIZE) % BLOCK_SIZE;
        val blocks = createBlocks(ArrayUtils.addAll(data, new byte[padding]));

        return
                ArrayUtils.addAll(
                        ByteBuffer.allocate(8).putLong(encipherMode.getCode()).array(),
                        ArrayUtils.addAll(
                                ArrayUtils.addAll(byteIV, ByteBuffer.allocate(8).putLong(realLength).array()),
                                switch (encipherMode) {
                                    case ECB -> ECBEncipher(blocks);
                                    case CBC -> CBCEncipher(blocks);
                                    case OFB -> OFBMode(blocks);
                                    case PCBC -> PCBCEncipher(blocks);
                                    default -> throw new RuntimeException("Not supported mode!!!");
                                }));
    }

    @SneakyThrows
    public byte[] decipher(byte[] data) {
        // read IV from first 8 bytes
        val encipherMode = EncipherMode.getByCode((int)ByteBuffer.wrap(ArrayUtils.subarray(data, 0, BLOCK_SIZE)).getLong());
        byteIV = ArrayUtils.subarray(data, BLOCK_SIZE, BLOCK_SIZE * 2);
        val realLength = ByteBuffer.wrap(ArrayUtils.subarray(data, BLOCK_SIZE + byteIV.length,
                byteIV.length + BLOCK_SIZE * 2)).getLong();
        // skip mode, IV and length
        val blocks = createBlocks(data).subList(3, data.length / BLOCK_SIZE);

        byte[] res = switch (encipherMode) {
            case ECB -> ECBDecipher(blocks);
            case CBC -> CBCDecipher(blocks);
            case OFB -> OFBMode(blocks);
            case PCBC -> PCBCDecipher(blocks);
            default -> throw new RuntimeException("Not supported mode!!!");
        };

        return ArrayUtils.subarray(res, 0, (int)realLength);
    }

    private byte[] setBlock(byte[] block, BlockCipherMode mode) {
        val pair = callCipher(unsignedInt(bytesToLong(block)), unsignedInt((bytesToLong(block)) >> 32), mode);

        return ArrayUtils.toPrimitive(
                Stream.of(pair.left, pair.right)
                        .map(val -> ArrayUtils.subarray(ArrayUtils.toObject(longToBytes(val)), 0, Integer.BYTES))
                        .flatMap(Arrays::stream)
                        .toArray(Byte[]::new)
        );
    }

    private long F(long xl) {
        long a = (xl & 0xff000000) >> 24;
        long b = (xl & 0x00ff0000) >> 16;
        long c = (xl & 0x0000ff00) >> 8;
        long d = xl & 0x000000ff;

        // Perform all ops as longs then and out the last 32-bits to obtain the integer
        long f = (s[0][(int) a] + s[1][(int) b]) % MODULUS;
        f = xor(f, s[2][(int) c]);
        f += s[3][(int) d];
        f %= MODULUS;
        return f;
    }
}
