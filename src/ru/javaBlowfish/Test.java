package ru.javaBlowfish;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;

public class Test
{
    public static void main(String[] args) throws IOException {
      Blowfish blowfish = new Blowfish("qwertyui");
        String encryptedString = blowfish.encrypt("qwertyui");
        System.out.println(new String((blowfish.decrypt(encryptedString,8)).getBytes(),"UTF-8"));

    }
}
