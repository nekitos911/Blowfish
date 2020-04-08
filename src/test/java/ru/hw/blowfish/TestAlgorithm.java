package ru.hw.blowfish;

import lombok.val;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import ru.hw.blowfish.enums.EncipherMode;

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
}

