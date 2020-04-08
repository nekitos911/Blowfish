package ru.hw.blowfish;

import lombok.val;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import ru.hw.blowfish.enums.EncipherMode;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class TestAlgorithm
{
    //    @RepeatedTest(20)
    @ParameterizedTest
    @EnumSource(EncipherMode.class)
    void testAlgorithms(EncipherMode mode) {
        val inputData = RandomStringUtils.randomAscii(0, 1_000_000).getBytes();
        val pwd = RandomStringUtils.randomAscii(4, 56);

        byte[] encipheredData = new Blowfish(pwd).encipher(inputData, mode);
        byte[] decipheredData = new Blowfish(pwd).decipher(encipheredData);

        assertArrayEquals(inputData, decipheredData);
    }

    @Test
    public void test() {
        for (int i = 0; i < 10; i++) {
            System.out.println((int)((10 * LCGRandom.next())));
        }
    }
}

class LCGRandom {

    public static double next() {
        seed = (seed * a + c) % m;
        return (double)seed / MAX_SEED;
    }

    // GCC standard
    private static final long a = 1103515245L;
    private static final long c = 12345L;
    private static final long m = 1L << 32;
    private static final long MAX_SEED = m - 1;
    private static long seed = System.currentTimeMillis() % MAX_SEED;
}
