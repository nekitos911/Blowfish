package ru.javaBlowfish;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

public class Blowfish {
    private static final long modulus = (long) Math.pow(2L, 32);
    private static final int N = 16;
    private static final int MAXBYTES = 56;
    private static final int ROUNDS = 16;
    private long[] p = new long[N + 2];
    private long[][] s = new long[4][256];
    private String myString = "qwertyuЙ";
    private String IV = "12345678";
    private byte[] byteIV = IV.getBytes("Cp1251");
    //    private char[] IV;
    private long Xl,Xr;
    private boolean IVSet;
    public Blowfish(String hexKey) throws IOException {
        if(hexKey.length() > 56)
            throw new ArrayIndexOutOfBoundsException("String should be more less 56");
        else if(hexKey.length() < 4)
            throw new StringIndexOutOfBoundsException("String should be more than 3");
        Xl = Xr = 0;
        IVSet = false;
        System.arraycopy(RandomNumberTables.bf_P,0,p,0,N + 2);
        System.arraycopy(RandomNumberTables.bf_S,0,s,0,RandomNumberTables.bf_S.length);
        byte[] byteKey = hexKey.getBytes("Cp1251");
        setupKey(byteKey,byteKey.length);
    }

    private void setupKey(byte[] key,int length) {
        int j = 0;
        for (int i = 0; i < N + 2; i++) {
            int data = ((key[j]) << 24) + ((key[(j + 1)]) << 16)
                    + ((key[(j + 2)]) << 8) + (key[(j + 3)]);
            p [i] = xor(p[i],data);
            j = (j + 4) % length ;
        }
        Xl = 0;
        Xr = 0;


        for (int i = 0; i < N + 2; i += 2) {
            encipher();
            p[i] = Xl;
            p[i + 1] = Xr;
        }

        for (int i = 0; i < 4; i++) {
            for (int k = 0; k < 256; k += 2) {
                encipher();
                s[i][k] = Xl;
                s[i][k + 1] = Xr;
            }
        }
    }

    private long bytesToLong(byte[] key) {
        return (long)key[7] << 56 & 0xFF00000000000000L | (long)key[6] << 48 & 0x00FF000000000000L |
                (long)key[5] << 40 & 0x0000FF0000000000L | (long)key[4] << 32 & 0x000000FF00000000L |
                (long)key[3] << 24 & 0x00000000FF000000L | (long)key[2] << 16 & 0x0000000000FF0000L |
                (long)key[1] << 8 & 0x000000000000FFF0L | (long)key[0] & 0x00000000000000FFL;

    }

    public byte[] longToBytes(long value) {
        byte[] array = new byte[8];
        for (int i = 0; i < 8; i++) {
            array[i] = (byte) ((value >> (i * 8)) & 0xFF);
        }
        return array;
    }

    private void encipher() {
        Xl = xor(Xl,p[0]);
        for (int i = 0; i < ROUNDS; i += 2) {
            Xr = xor(Xr,xor(F(Xl),p[i + 1]));
            Xl = xor(Xl,xor(F(Xr),p[i + 2]));
        }
        Xr = xor(Xr,p[17]);
        //Swap Xl and Xr
        long temp = Xr;
        Xr = Xl;
        Xl = temp;
    }

    private void decipher() {
        Xl = xor(Xl,p[N + 1]);
        for (int i = N; i > 0; i -= 2) {
            Xr = xor(Xr,xor(F(Xl),p[i]));
            Xl = xor(Xl,xor(F(Xr),p[i - 1]));
        }
        Xr = xor(Xr,p[0]);
        //Swap Xl and Xr
        long temp = Xr;
        Xr = Xl;
        Xl = temp;
    }

    public String encrypt(String data) throws UnsupportedEncodingException {
        int length = data.getBytes("Windows-1251").length;
        if(length % 8 != 0) {
            StringBuilder dataBuilder = new StringBuilder(data);
            while (dataBuilder.length() % 8 != 0) {
                dataBuilder.append(String.valueOf(8 - (length % 8)));
            }
            data = dataBuilder.toString();
        }
        byte[] byteData = new byte[8];
        System.arraycopy(data.getBytes("Windows-1251"),0,byteData,0,8);
        for (int i = 0; i < 8; i++) {
            byteData[i] ^= byteIV[i];
        }
        StringBuilder encryptedString = new StringBuilder();
        encryptedString.insert(0,setBlock(byteData,"encrypt"));
        for (int i = 8; i < data.length(); i+= 8) {
            for (int j = 0; j < 8; j++) {
               byteData[j] ^= data.getBytes("Cp1251")[j + i];
            }
            encryptedString = new StringBuilder(setBlock(byteData,"encrypt"));
        }
        return encryptedString.toString();
    }

    public String decrypt(String data,int fileLength) throws UnsupportedEncodingException {
        byte[] byteData = data.getBytes("Cp1251");
        StringBuilder decryptedString = new StringBuilder();
        decryptedString.append(setBlock(byteData,"decrypt"));
        byteData = decryptedString.toString().getBytes("Cp1251");
        for (int i = 0; i < 8; i++) {
            byteData[i] ^= byteIV[i];
        }
        decryptedString = new StringBuilder(new String(byteData));
        byteData = data.getBytes("UTF-8");
        //TODO Неверно шифрует блоки
        for (int i = 8; i < fileLength; i+= 8) {
            for (int j = 0; j < 8; j++) {
                byte tmpData = data.getBytes("Cp1251")[j + i];
                //byteData[j] ^= setBlock(b)
            }
            decryptedString.append(setBlock(byteData,"decrypt"));
        }
        return decryptedString.toString();
    }

    private String setBlock(byte[] block, String mode) {
        byte[] tmp = new byte[8];
        byte[] newTmp = new byte[4];

        if (mode.equals("encrypt")) {
            Xr = ((bytesToLong(block)) >> 32);
            Xl = (int)bytesToLong(block);
            encipher();
        } else if (mode.equals("decrypt")) {
            decipher();
        }
        System.arraycopy(longToBytes(Xl),0,tmp,0,4);
        System.arraycopy(longToBytes(Xr),0,tmp,4,4);
        return new String(tmp);
    }

    private long F(long xl) {
        long a = (xl & 0xff000000) >> 24;
        long b = (xl & 0x00ff0000) >> 16;
        long c = (xl & 0x0000ff00) >> 8;
        long d = xl & 0x000000ff;

        // Perform all ops as longs then and out the last 32-bits to obtain the integer
        long f = (s[0][(int) a] + s[1][(int) b]) % modulus;
        f = xor(f, s[2][(int) c]);
        f += s[3][(int) d];
        f %= modulus;
        return f;
    }

    private String byteToHex(char x) {
        String hex = "0123456789ABCDEF";
        String result ="";
        result += hex.toCharArray()[x / 16];
        result += hex.toCharArray()[x % 16];
        return result;
    }

    private long xor(long a,long b) {
        return unsignedLong(a ^ b);
    }

    private long unsignedLong(long number) {
        return number & 0xffffffffL;
    }


}
