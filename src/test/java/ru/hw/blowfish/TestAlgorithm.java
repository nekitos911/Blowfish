package ru.hw.blowfish;

import lombok.val;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import ru.hw.blowfish.enums.EncipherMode;
import static org.junit.jupiter.api.Assertions.assertEquals;

class TestAlgorithm
{
    @ParameterizedTest
    @EnumSource(EncipherMode.class)
    void testAlgorithms(EncipherMode mode) {
        val inputData = "Привет text to encipher!!!";

        String encipheredData = new Blowfish("qwertyui", mode).encipher(inputData);
        String decipheredData = new Blowfish("qwertyui", mode).decipher(encipheredData);

        assertEquals(inputData, decipheredData);
    }
}
