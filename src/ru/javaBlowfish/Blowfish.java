package ru.javaBlowfish;

import java.io.IOException;

public class Blowfish {
    private static final long modulus = (long) Math.pow(2L, 32);
    private static final int N = 16;
    private static final int MAXBYTES = 56;
    private static final int ROUNDS = 16;
    private long[] p = new long[N + 2];
    private long[][] s = new long[4][256];
    private String myString = "privettnq";
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
//        int[] intArr = byte2int(byteKey);
//        byte[] byteArr = int2byte(intArr);
        setupKey(byteKey,byteKey.length);
        //encrypt(myString);
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

    private void encipher() {
        Xl = xor(Xl,p[0]);
        for (int i = 0; i < ROUNDS; i ++) {
            Xr = xor(Xr,xor(F(Xl),p[i]));
            Xl = xor(Xl,xor(F(Xr),p[++i]));
        }
        Xr = xor(Xr,p[17]);
        //Swap Xl and Xr
        long temp = Xr;
        Xr = Xl;
        Xl = temp;
    }

    public void encrypt(String data) {
        if(data.length() % 8 != 0) {
            StringBuilder dataBuilder = new StringBuilder(data);
            while (dataBuilder.length() % 8 != 0) {
                dataBuilder.append("0");
            }
            data = dataBuilder.toString();
        }
        byte[] binaryData = data.getBytes();
        //int[] intData = byte2int(binaryData);
        byte[] IVByte = IV.getBytes();
        System.out.println(IVByte[0]);
//        for (int i = 0; i < binaryData.length ; i++) {
//            binaryData[i] ^=
//        }

    }

    private void decipher() {
        Xl = xor(Xl,p[N + 1]);
        for (int i = N; i > 0; i --) {
            Xr = xor(Xr,xor(F(Xl),p[i]));
            Xr = xor(Xl,xor(F(Xr),p[--i]));
        }
        Xr = xor(Xr,p[N + 1]);
        //Swap Xl and Xr
        long temp = Xr;
        Xr = Xl;
        Xl = temp;
    }

    private long F(long X) {
        long a = unsignedLong(X) >> 24;
        long b = unsignedLong(X) >> 16;
        long c = unsignedLong(X) >> 8;
        long d = unsignedLong(X);

        // Perform all ops as longs then and out the last 32-bits to obtain the integer
        long f = (s[0][(int)a] + s[1][(int)b]) % modulus;
        f = xor(f,s[2][(int)c]);
        f += s[3][(int)d];
        f %= modulus;
        return f;
    }

//    private int[] byte2int(byte[] buf){
//        int[] intArr = new int[buf.length / 4];
//        int offset = 0;
//
//        for (int i = 0; i < intArr.length; i++) {
//            intArr[i] =  (buf[3 + offset] & 0xFF) | ((buf[2 + offset] & 0xFF) << 8) |
//                    ((buf[1 + offset] & 0xFF) << 16) | ((buf[offset] & 0xFF) << 24);
//            offset +=4;
//        }
//        return intArr;
//    }

//    private byte[] int2byte(int[] src){
//        int srcLength = src.length;
//        byte[] dst = new byte[srcLength << 2];
//
//        for (int i=0; i<srcLength; i++) {
//            int x = src[i];
//            int j = i << 2;
//            dst[j++] = (byte) ((x >>> 24) & 0xff);
//
//            dst[j++] = (byte) ((x >>> 16) & 0xff);
//            dst[j++] = (byte) ((x >>> 8) & 0xff);
//            dst[j++] = (byte) ((x) & 0xff);
//        }
//        return dst;
//    }

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
