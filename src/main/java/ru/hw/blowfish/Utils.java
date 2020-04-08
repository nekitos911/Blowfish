package ru.hw.blowfish;

import com.google.common.collect.Lists;
import com.google.common.primitives.Bytes;
import lombok.val;
import org.apache.commons.lang3.ArrayUtils;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class Utils {
    public static final long MODULUS = (long)1 << 32;
    public static final int N = 16;
    public static final int ROUNDS = 16;
    public static final int BLOCK_SIZE = Long.BYTES;

    public static long xor(long a, long b) {
        return unsignedInt(a ^ b);
    }

    public static long unsignedInt(long number) {
        return number & 0xffffffffL;
    }

    public static long bytesToLong(byte[] key) {
        val copyArr = Arrays.copyOf(key, key.length);
        ArrayUtils.reverse(copyArr);
        return ByteBuffer.wrap(copyArr).getLong();
    }

    public static byte[] longToBytes(long value) {
        val ret = ByteBuffer.allocate(8).putLong(value).array();
        ArrayUtils.reverse(ret);
        return ret;
    }

    public static List<byte[]> createBlocks(byte[] data) {
        return Lists.partition(Bytes.asList(data), BLOCK_SIZE)
                .parallelStream()
                .map(bytes -> ArrayUtils.toPrimitive(bytes.toArray(new Byte[0])))
                .collect(Collectors.toList());
    }
}
