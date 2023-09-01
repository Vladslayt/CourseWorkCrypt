package com.example.courseworkcrypt.algorithms;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

import static java.math.BigInteger.ONE;

public class RC6 {
    private static final int R = 20;
    private static int[] RoundKey = new int[2 * R + 4];
    private static final int _w = 32;
    private static byte[] _mainKey;
    private static final int P32 = 0xB7E15163;
    private static final int Q32 = 0x9E3779B9;
    private static final int BLOCK_SIZE = 16;

    public byte[] getMainKey() {
        return _mainKey;
    }

    public static void setMainKey(byte[] mainKey) {
        _mainKey = mainKey;
    }

    public int getBlockSize() {
        return BLOCK_SIZE;
    }

    /* Генерация ключа */
    public static void generateKey(int keyLength) {
        if (_mainKey == null) {
            // Если main key не задан заранее, используем генератор случайных ключей
            SecureRandom random = new SecureRandom();
            _mainKey = new byte[keyLength / 8];
            random.nextBytes(_mainKey);
        }

        int c = 0;
        int i, j;
        // В зависимости от размера ключа выбираем на сколько блоков разбивать main key
        switch (keyLength) {
            case 128 -> c = 4;
            case 192 -> c = 6;
            case 256 -> c = 8;
        }
        int[] L = new int[c];
        for (i = 0; i < c; i++) {
            L[i] = ByteBuffer.wrap(_mainKey, i * 4, 4).getInt();
        }
        // Сама генерация раундовых ключей в соответствие с документацией
        RoundKey[0] = P32;
        for (i = 1; i < 2 * R + 4; i++) {
            RoundKey[i] = RoundKey[i - 1] + Q32;
        }
        int A, B;
        A = B = 0;
        i = j = 0;
        int V = 3 * Math.max(c, 2 * R + 4); // максимум из раундов или количества слов в ключе
        for (int s = 1; s <= V; s++) {
            A = RoundKey[i] = leftShift(RoundKey[i] + A + B, 3);
            B = L[j] = leftShift(L[j] + A + B, A + B);
            i = (i + 1) % (2 * R + 4);
            j = (j + 1) % c;
        }
    }

    // Сдвиг влево без потери
    private static int leftShift(int value, int shift) {
        return (value << shift) | (value >>> (_w - shift));
    }

    // Сдвиг вправо без потери
    private static int rightShift(int value, int shift) {
        return (value >>> shift) | (value << (_w - shift));
    }

    // Разбивает на массив байтов
    private static byte[] toArrayBytes(int[] ints, int length) {
        byte[] arrayBytes = new byte[length * 4];
        for (int i = 0; i < length; i++) {
            ByteBuffer buffer = ByteBuffer.allocate(4).putInt(ints[i]);
            System.arraycopy(buffer.array(), 0, arrayBytes, i * 4, 4);
        }
        return arrayBytes;
    }

    public static byte[] encryptBloc(byte[] plaintext) {
        int A, B, C, D;
        int length = plaintext.length;
        while (length % BLOCK_SIZE != 0) {
            length++;
        }
        byte[] text = new byte[length];
        System.arraycopy(plaintext, 0, text, 0, plaintext.length);
        byte[] ciphertext = new byte[length];
        for (int k = 0; k < text.length; k += BLOCK_SIZE) {
            A = ByteBuffer.wrap(text, k, 4).getInt();
            B = ByteBuffer.wrap(text, k + 4, 4).getInt();
            C = ByteBuffer.wrap(text, k + 8, 4).getInt();
            D = ByteBuffer.wrap(text, k + 12, 4).getInt();

            B += RoundKey[0];
            D += RoundKey[1];
            for (int i = 1; i <= R; i++) {
                int t = leftShift((B * (2 * B + 1)), (int) (Math.log(_w) / Math.log(2)));
                int u = leftShift((D * (2 * D + 1)), (int) (Math.log(_w) / Math.log(2)));
                A = leftShift((A ^ t), u) + RoundKey[i * 2];
                C = leftShift((C ^ u), t) + RoundKey[i * 2 + 1];
                int temp = A;
                A = B;
                B = C;
                C = D;
                D = temp;
            }
            A += RoundKey[2 * R + 2];
            C += RoundKey[2 * R + 3];

            int[] tempWords = new int[]{A, B, C, D};
            byte[] block = toArrayBytes(tempWords, 4);
            System.arraycopy(block, 0, ciphertext, k, BLOCK_SIZE);
        }
        return ciphertext;
    }

    public static byte[] decryptBloc(byte[] ciphertext) {
        int A, B, C, D;
        int length = ciphertext.length;
        byte[] plaintext = new byte[length];
        for (int k = 0; k < ciphertext.length; k += BLOCK_SIZE) {
            A = ByteBuffer.wrap(ciphertext, k, 4).getInt();
            B = ByteBuffer.wrap(ciphertext, k + 4, 4).getInt();
            C = ByteBuffer.wrap(ciphertext, k + 8, 4).getInt();
            D = ByteBuffer.wrap(ciphertext, k + 12, 4).getInt();

            C -= RoundKey[2 * R + 3];
            A -= RoundKey[2 * R + 2];
            for (int i = R; i >= 1; i--) {
                int temp = D;
                D = C;
                C = B;
                B = A;
                A = temp;
                int u = leftShift((D * (2 * D + 1)), (int) (Math.log(_w) / Math.log(2)));
                int t = leftShift((B * (2 * B + 1)), (int) (Math.log(_w) / Math.log(2)));
                C = rightShift((C - RoundKey[2 * i + 1]), t) ^ u;
                A = rightShift((A - RoundKey[2 * i]), u) ^ t;
            }
            D -= RoundKey[1];
            B -= RoundKey[0];

            int[] tempWords = new int[]{A, B, C, D};
            byte[] block = toArrayBytes(tempWords, 4);
            System.arraycopy(block, 0, plaintext, k, BLOCK_SIZE);
        }
        return plaintext;
    }

    public enum encryptionMode{

        ECB,
        CBC,
        CFB,
        OFB,
        CTR,
        RD
    }

//    public static byte[] xor(byte[] arr1, byte[] arr2) {
//        byte[] arr3 = new byte[Math.min(arr1.length, arr2.length)];
//
//        int i = 0;
//        for(byte b : arr3){
//            arr3[i] = (byte) (arr1[i]^arr2[i]);
//            i++;
//        }
//        return arr3;
//    }
    private static byte[] xor(byte[] valueLeft, byte[] valueRight)
    {
        for (int i = 0; i < valueLeft.length; i++)
        {
            valueLeft[i] = (byte)(valueLeft[i] ^ valueRight[i]);
        }
        return valueLeft;
    }

    public static byte[] encrypt(byte[] in, byte[] key, byte[] iv, encryptionMode encMode){
        setMainKey(key);
        generateKey(128);

        int lenght = 16 - in.length % 16;
        int i;
        byte[] padding = new byte[lenght];
        padding[0] = (byte) 0x80;
        int count = 0;
        byte[] tmp = new byte[in.length + lenght];
        byte[] bloc = new byte[16];
        switch (encMode) {
            case ECB -> {
                for (i = 0; i < in.length + lenght; i++) {
                    if (i > 0 && i % 16 == 0) {
                        bloc = encryptBloc(bloc);
                        System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
                    }
                    if (i < in.length)
                        bloc[i % 16] = in[i];
                    else {
                        bloc[i % 16] = padding[count % 16];
                        count++;
                    }
                }
                if (bloc.length == 16) {
                    bloc = encryptBloc(bloc);
                    System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
                }
            }
            case CBC -> {
                for (i = 0; i < in.length + lenght; i++) {
                    if (i > 0 && i % 16 == 0) {
                        xor(bloc, iv);
                        bloc = encryptBloc(bloc);
                        System.arraycopy(bloc, 0, iv, 0, bloc.length);
                        System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
                    }
                    if (i < in.length)
                        bloc[i % 16] = in[i];
                    else {
                        bloc[i % 16] = padding[count % 16];
                        count++;
                    }

                }
                if (bloc.length == 16) {
                    xor(bloc, iv);
                    bloc = encryptBloc(bloc);
                    System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
                }
            }
            case CFB -> {
                for (i = 0; i < in.length + lenght; i++) {
                    if (i > 0 && i % 16 == 0) {
                        iv = encryptBloc(iv);
                        bloc = xor(iv, bloc);
                        System.arraycopy(bloc, 0, iv, 0, bloc.length);
                        System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);

                    }
                    if (i < in.length)
                        bloc[i % 16] = in[i];
                    else {
                        bloc[i % 16] = padding[count % 16];
                        count++;
                    }

                }
                if (bloc.length == 16) {
                    iv = encryptBloc(iv);
                    bloc = xor(iv, bloc);
                    System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
                }
            }
            case OFB -> {
                for (i = 0; i < in.length + lenght; i++) {
                    if (i > 0 && i % 16 == 0) {
                        iv = encryptBloc(iv);
                        bloc = xor(iv, bloc);
                        System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);

                    }
                    if (i < in.length)
                        bloc[i % 16] = in[i];
                    else {
                        bloc[i % 16] = padding[count % 16];
                        count++;
                    }

                }
                if (bloc.length == 16) {
                    iv = encryptBloc(iv);
                    bloc = xor(iv, bloc);
                    System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
                }
            }
            case CTR -> {
                for (i = 0; i < in.length + lenght; i++) {
                    if (i > 0 && i % 16 == 0) {
                        iv = ((new BigInteger(iv)).add(ONE)).toByteArray();
                        bloc = xor(encryptBloc(iv), bloc);
                        System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);

                    }
                    if (i < in.length)
                        bloc[i % 16] = in[i];
                    else {
                        bloc[i % 16] = padding[count % 16];
                        count++;
                    }

                }
                if (bloc.length == 16) {
                    iv = ((new BigInteger(iv)).add(ONE)).toByteArray();
                    bloc = xor(encryptBloc(iv), bloc);
                    System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
                }
            }
            case RD -> {
                BigInteger rd = new BigInteger(Arrays.copyOfRange(iv, 0, 8));
                for (i = 0; i < in.length + lenght; i++) {
                    if (i > 0 && i % 16 == 0) {
                        iv = ((new BigInteger(iv)).add(rd)).toByteArray();
                        bloc = encryptBloc(xor(iv, bloc));
                        System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
                    }
                    if (i < in.length)
                        bloc[i % 16] = in[i];
                    else {
                        bloc[i % 16] = padding[count % 16];
                        count++;
                    }

                }
                if (bloc.length == 16) {
                    iv = ((new BigInteger(iv)).add(rd)).toByteArray();
                    bloc = encryptBloc(xor(iv, bloc));
                    System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
                }
            }
            default -> throw new IllegalStateException("Unexpected value: " + encMode);
        }
        return tmp;


    }
    public static byte[] decrypt(byte[] in,byte[] key, byte[] iv, encryptionMode encMode) {
        setMainKey(key);
        generateKey(128);
        byte[] tmp = new byte[in.length];
        byte[] bloc = new byte[16];
        int i;
        switch (encMode) {
            case ECB -> {
                for (i = 0; i < in.length; i++) {
                    if (i > 0 && i % 16 == 0) {
                        bloc = decryptBloc(bloc);
                        System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
                    }
                    bloc[i % 16] = in[i];
                }
                bloc = decryptBloc(bloc);
                System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
            }
            case CBC -> {
                byte[] bloc1 = new byte[16];
                for (i = 0; i < in.length; i++) {
                    if (i > 0 && i % 16 == 0) {
                        System.arraycopy(bloc, 0, bloc1, 0, 16);
                        bloc = decryptBloc(bloc);
                        xor(bloc, iv);
                        System.arraycopy(bloc1, 0, iv, 0, 16);
                        System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
                    }
                    bloc[i % 16] = in[i];
                }
                bloc = decryptBloc(bloc);
                xor(bloc, iv);
                System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
            }
            case CFB -> {
                byte[] bloc2 = new byte[16];
                for (i = 0; i < in.length; i++) {
                    if (i > 0 && i % 16 == 0) {
                        System.arraycopy(bloc, 0, bloc2, 0, 16);
                        iv = encryptBloc(iv);
                        bloc = xor(iv, bloc);
                        System.arraycopy(bloc2, 0, iv, 0, 16);
                        System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
                    }
                    bloc[i % 16] = in[i];
                }
                iv = encryptBloc(iv);
                bloc = xor(iv, bloc);
                System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
            }
            case OFB -> {
                for (i = 0; i < in.length; i++) {
                    if (i > 0 && i % 16 == 0) {
                        iv = encryptBloc(iv);
                        bloc = xor(iv, bloc);
                        System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
                    }
                    bloc[i % 16] = in[i];
                }
                iv = encryptBloc(iv);
                bloc = xor(iv, bloc);
                System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
            }
            case CTR -> {
                for (i = 0; i < in.length; i++) {
                    if (i > 0 && i % 16 == 0) {
                        iv = ((new BigInteger(iv)).add(ONE)).toByteArray();
                        bloc = xor(encryptBloc(iv), bloc);
                        System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
                    }
                    bloc[i % 16] = in[i];
                }
                iv = ((new BigInteger(iv)).add(ONE)).toByteArray();
                bloc = xor(encryptBloc(iv), bloc);
                System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
            }
            case RD -> {
                BigInteger rd = new BigInteger(Arrays.copyOfRange(iv, 0, 8));
                for (i = 0; i < in.length; i++) {
                    if (i > 0 && i % 16 == 0) {
                        iv = ((new BigInteger(iv)).add(rd)).toByteArray();
                        bloc = xor(iv, decryptBloc(bloc));
                        System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
                    }
                    bloc[i % 16] = in[i];
                }
                iv = ((new BigInteger(iv)).add(rd)).toByteArray();
                bloc = encryptBloc(xor(iv, bloc));
                System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
            }
            default -> throw new IllegalStateException("Unexpected value: " + encMode);
        }
        tmp = deletePadding(tmp);

        return tmp;
    }

    public static byte[] deletePadding(byte[] input) {
        int count = 0;
        int i = input.length - 1;
        while (input[i] == 0) {
            count++;
            i--;
        }
        byte[] tmp = new byte[input.length - count - 1];
        System.arraycopy(input, 0, tmp, 0, tmp.length);
        return tmp;
    }
}

