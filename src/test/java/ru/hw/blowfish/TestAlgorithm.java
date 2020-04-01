package ru.hw.blowfish;

import lombok.val;
import org.junit.Assert;
import org.junit.Test;
import ru.hw.blowfish.Blowfish;

import java.nio.charset.Charset;

public class TestAlgorithm
{
    @Test
    public void testEcbMode() throws Exception {
        val inputData = "test text to encipher!!!";
        val blowfish = new Blowfish("qwertyui");

        String encipheredData = blowfish.encipher(inputData);
        String decipheredData = blowfish.decipher(encipheredData);

        Assert.assertEquals(inputData, decipheredData);
    }
}
