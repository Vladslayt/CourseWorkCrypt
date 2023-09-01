package com.example.courseworkcrypt.server;

import com.example.courseworkcrypt.algorithms.LUC;

import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

public class Server {
    LUC luc;
    private final byte[] sessionKey;
    private final byte[] iv;

    public Server(){
        luc = new LUC(12);
        sessionKey = getRandomBytes(32);
        iv = getRandomBytes(16);
    }

    public static byte[] getRandomBytes(int size){
        SecureRandom rd = new SecureRandom();
        byte[] arr = new byte[size];
        rd.nextBytes(arr);
        return arr;
    }
    public BigInteger[] getSessionKey(BigInteger publicKey, BigInteger N){
        return luc.encrypt(sessionKey, publicKey, N);
    }
    public BigInteger[] getIV(BigInteger publicKey, BigInteger N){
        return luc.encrypt(iv, publicKey, N);
    }

    public void getFile(byte[] fileByte, String fileName){
        File file = new File("D:\\Программы\\IntelliJ IDEA Community Edition 2020.3.2\\CourseWorkCrypt\\src\\main\\resources\\server\\" + fileName + ".enc" );

        try {
            FileOutputStream os = new FileOutputStream(file);
            os.write(fileByte);
            os.close();
        } catch (Exception e) {
            System.out.println(e);
        }

    }
    public File sendFile(String fileName){
        return(new File(fileName));
    }

}


