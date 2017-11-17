package ru.javaBlowfish;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;

public class Blowfish {
    private static final long modulus = (long) Math.pow(2L, 32);
    private static final int N = 16;
    private static final int MAXBYTES = 56;
    private static final int ROUNDS = 16;
    private long[] p = new long[N + 2];
    private long[][] s = new long[4][256];
    private String myString = "qwertyui";
    private String IV = "12345678";
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
        byte[] byteKey = hexKey.getBytes();
        setupKey(byteKey,byteKey.length);
        encrypt(myString);
    }

    private void setupKey(byte[] key,int length) {
        int j = 0;
        for (int i = 0; i < N + 2; i++) {
            int data = ((key[j % length] & 0xFF) << 24) + ((key[(j + 1) % length] & 0xFF) << 16)
                    + ((key[(j + 2) % length] & 0xFF) << 8) + (key[(j + 3) % length] & 0xFF);
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

    public long bytesToLong(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.put(bytes);
        buffer.flip();//need flip
        return buffer.getLong();
    }

    private char[] longToChars(long value) {
        ByteBuffer buf = ByteBuffer.allocate(8);
        buf.putLong(value);
        buf.rewind();
        return buf.asCharBuffer().array();
    }
    public byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(x);
        return buffer.array();
    }
    public byte[] intToBytes(int x) {
        ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
        buffer.putLong(x);
        return buffer.array();
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

    public void encrypt(String data) throws UnsupportedEncodingException {
        if(data.length() % 8 != 0) {
            StringBuilder dataBuilder = new StringBuilder(data);
            while (dataBuilder.length() % 8 != 0) {
                dataBuilder.append("0");
            }
            data = dataBuilder.toString();
        }
        byte[] binaryData = data.getBytes("Cp1251");
        long longData;
        byte[] tmp = data.substring(0,8).getBytes("Cp1251");
        System.out.println(tmp[0]);
        longData = bytesToLong(tmp);
        byte[] IVByte = IV.getBytes();
        long xorArr;
       // xorArr = xor(longData,bytesToLong(IVByte));
        //System.out.println(xorArr + " xorArr");
        xorArr = encryptBlock(Long.reverseBytes(longData));
        xorArr = decryptBlock(Long.reverseBytes(xorArr));
        //xorArr = xor(xorArr,bytesToLong(IVByte));
        for (int i = 0; i < 8; i++) {
            System.out.print((char)longToBytes(xorArr)[i]);
        }
    }

    private long encryptBlock(long block) {
        byte[] tmp = new byte[8];
        Xr = (int) ((block >> 32));
        Xl = (int)block;
        System.out.println("Xl " + (Xl));
        System.out.println("Xr " + Xr);
        encipher();
        System.out.println("Xl after " + Xl);
        System.out.println("Xr after " + Xr);
        System.arraycopy(BigInteger.valueOf(Long.reverseBytes(Xl)).toByteArray(),0,tmp,0,4);
        System.arraycopy(BigInteger.valueOf(Long.reverseBytes(Xr)).toByteArray(),0,tmp,4,4);
        return bytesToLong(tmp);
    }

    private long decryptBlock(long block) {
        byte[] tmp = new byte[8];
        Xr = (int) ((block >> 32));
        Xl = (int)(block);
        System.out.println("Xl " + Xl);
        System.out.println("Xr " + Xr);
        decipher();
        System.out.println("Xl after " + Xl);
        System.out.println("Xr after " + Xr);
        System.arraycopy(BigInteger.valueOf(Long.reverseBytes(Xl)).toByteArray(),0,tmp,0,4);
        System.arraycopy(BigInteger.valueOf(Long.reverseBytes(Xr)).toByteArray(),0,tmp,4,4);
        return bytesToLong(tmp);

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
