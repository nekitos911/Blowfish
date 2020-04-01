package ru.hw.blowfish;

import com.google.common.collect.Lists;
import lombok.SneakyThrows;
import lombok.Synchronized;
import lombok.val;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.RandomStringUtils;
import ru.hw.blowfish.enums.BlockCipherMode;
import ru.hw.blowfish.enums.EncipherMode;

import static ru.hw.blowfish.Utils.xor;
import static ru.hw.blowfish.Utils.unsignedLong;
import static ru.hw.blowfish.Utils.createBlocks;
import static ru.hw.blowfish.Utils.MODULUS;
import static ru.hw.blowfish.Utils.ROUNDS;
import static ru.hw.blowfish.Utils.N;
import static ru.hw.blowfish.Utils.BLOCK_SIZE;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class Blowfish {
    private long[] p = new long[N + 2];
    private long[][] s = new long[4][256];
    private byte[] byteIV;
    private long Xl;
    private long Xr;
    private EncipherMode encipherMode;

    public Blowfish(String hexKey) {
        this(hexKey, EncipherMode.ECB);
    }

    @SneakyThrows
    public Blowfish(String hexKey, EncipherMode encipherMode) {
        if (hexKey.length() > 56)
            throw new ArrayIndexOutOfBoundsException("String should be more less 56");
        else if (hexKey.length() < 4)
            throw new StringIndexOutOfBoundsException("String should be more than 3");

        this.encipherMode = encipherMode;
        setupKey(hexKey.getBytes());
    }

    private void setupKey(byte[] key) {
        System.arraycopy(RandomNumberTables.bf_P, 0, p, 0, N + 2);
        for (int i = 0; i < s.length; i++)
            System.arraycopy(RandomNumberTables.bf_S[i], 0, s[i], 0, s[i].length);

        int length = key.length;
        int j = 0;

        for (int i = 0; i < N + 2; i++) {
            p[i] &= 0xffffffffL;
            p[i] ^= key[j];
            j = (j + 1) % length;
        }

        for (int i = 0; i < N + 2; i += 2) {
            encipher();
            p[i] = Xl;
            p[i + 1] = Xr;
        }

        for (var sBucket : s) {
            for (int k = 0; k < 256; k += 2) {
                encipher();
                sBucket[k] = Xl;
                sBucket[k + 1] = Xr;
            }
        }
    }

    private long bytesToLong(byte[] key) {
        val copyArr = Arrays.copyOf(key, key.length);
        ArrayUtils.reverse(copyArr);
        return ByteBuffer.wrap(copyArr).getLong();
    }

    private byte[] longToBytes(long value) {
        val ret = ByteBuffer.allocate(8).putLong(value).array();
        ArrayUtils.reverse(ret);
        return ret;
    }

    private void encipher() {
        Xl = xor(Xl, p[0]);

        for (int i = 0; i < ROUNDS; i += 2) {
            Xr = xor(Xr, xor(F(Xl), p[i + 1]));
            Xl = xor(Xl, xor(F(Xr), p[i + 2]));
        }

        Xr = xor(Xr, p[N + 1]);
        //Swap Xl and Xr
        long temp = Xr;
        Xr = Xl;
        Xl = temp;
    }

    private void decipher() {
        Xl = xor(Xl, p[N + 1]);
        for (int i = N; i > 0; i -= 2) {
            Xr = xor(Xr, xor(F(Xl), p[i]));
            Xl = xor(Xl, xor(F(Xr), p[i - 1]));
        }
        Xr = xor(Xr, p[0]);
        //Swap Xl and Xr
        long temp = Xr;
        Xr = Xl;
        Xl = temp;
    }

    private String ECBMode(List<byte[]> blocks, BlockCipherMode mode) {
        return blocks.parallelStream()
                .map(block -> ArrayUtils.toPrimitive(ArrayUtils.toObject(block)))
                .map(block -> setBlock(block, mode))
                .map(String::new)
                .collect(Collectors.joining());
    }

    private String ECBEncipher(List<byte[]> blocks) {
        return ECBMode(blocks, BlockCipherMode.ENCIPHER);
    }

    private String ECBDecipher(List<byte[]> blocks) {
        return ECBMode(blocks, BlockCipherMode.DECIPHER);
    }

    private String CBCEncipher(List<byte[]> blocks) {
        val mode = BlockCipherMode.ENCIPHER;

        // проксорил с IV первый блок
        for (int i = 0; i < blocks.get(0).length; i++) {
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

        return blocks.parallelStream().map(String::new).collect(Collectors.joining());
    }

    private String CBCDecipher(List<byte[]> blocks) {
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

        return blocks.parallelStream().map(String::new).collect(Collectors.joining());
    }

    private String OFBMode(List<byte[]> blocks) {
        var byteIVCopy = ArrayUtils.clone(byteIV);

        for (byte[] bytes : blocks) {
            // Шифруем/Дешифруем IV
            byteIVCopy = setBlock(byteIVCopy, BlockCipherMode.ENCIPHER);

            // проксорил блоки (зашифрованный IV с блоком)
            for (int j = 0; j < BLOCK_SIZE; j++) {
                bytes[j] ^= byteIVCopy[j];
            }
        }

        return blocks.parallelStream().map(String::new).collect(Collectors.joining());
    }

    private String PCBCEncipher(List<byte[]> blocks) {
        val mode = BlockCipherMode.ENCIPHER;
        val blocksCopy = blocks.stream().map(ArrayUtils::clone).collect(Collectors.toList());

        // проксорил с IV первый блок
        for (int i = 0; i < blocks.get(0).length; i++) {
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
            int a = 0;
        }

        return blocks.parallelStream().map(String::new).collect(Collectors.joining());
    }

    private String PCBCDecipher(List<byte[]> blocks) {
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
            var a = setBlock(blocks.get(i), BlockCipherMode.DECIPHER);

            for (int j = 0; j < BLOCK_SIZE; j++) {
                a[j] ^= firstBlock[j];
            }

            blocks.set(i, a);
        }

        return blocks.parallelStream().map(String::new).collect(Collectors.joining());
    }

    @SneakyThrows
    public String encipher(String data) {
        // Set random IV
        byteIV = "12345678".getBytes()/*RandomStringUtils.randomAlphabetic(BLOCK_SIZE).getBytes()*/;
        val bytesData = data.getBytes();
        val realLength = bytesData.length;
        val padding = (BLOCK_SIZE - bytesData.length % BLOCK_SIZE) % BLOCK_SIZE;
        val blocks = createBlocks(ArrayUtils.addAll(bytesData, new byte[padding]));

        return
                new String(byteIV)
                        + new String(ByteBuffer.allocate(8).putLong(realLength).array())
                        + switch (encipherMode) {
                    case ECB -> ECBEncipher(blocks);
                    case CBC -> CBCEncipher(blocks);
                    case OFB -> OFBMode(blocks);
                    case PCBC -> PCBCEncipher(blocks);
                    default -> throw new RuntimeException("Not supported mode!!!");
                };
    }

    @SneakyThrows
    public String decipher(String data) {
        var bytesData = data.getBytes();
        // read IV from first 8 bytes
        byteIV = ArrayUtils.subarray(bytesData, 0, BLOCK_SIZE);
        val realLength = ByteBuffer.wrap(ArrayUtils.subarray(bytesData, byteIV.length, byteIV.length + BLOCK_SIZE)).getLong();
        // skip IV and length
        val blocks = createBlocks(bytesData).subList(2, bytesData.length / BLOCK_SIZE);

        String res = switch (encipherMode) {
            case ECB -> ECBDecipher(blocks);
            case CBC -> CBCDecipher(blocks);
            case OFB -> OFBMode(blocks);
            case PCBC -> PCBCDecipher(blocks);
            default -> throw new RuntimeException("Not supported mode!!!");
        };

        val bytes = res.getBytes();
        return new String(ArrayUtils.subarray(bytes, 0, (int)realLength));
    }

    private synchronized byte[] setBlock(byte[] block, BlockCipherMode mode) {
        byte[] tmp = new byte[8];

        Xl = unsignedLong(bytesToLong(block));
        Xr = unsignedLong((bytesToLong(block)) >> 32);
        switch (mode) {
            case DECIPHER -> decipher();
            case ENCIPHER -> encipher();
        }

        System.arraycopy(longToBytes(Xl),0,tmp,0,4);
        System.arraycopy(longToBytes(Xr),0,tmp,4,4);

        return tmp;
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
