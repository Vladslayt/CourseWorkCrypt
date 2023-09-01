package com.example.courseworkcrypt.server;
import com.example.courseworkcrypt.algorithms.RC6;
import com.example.courseworkcrypt.algorithms.LUC;

import java.io.*;
import java.math.BigInteger;

public class Client {
    private final LUC luc;
    private byte[] sessionKey;
    private byte[] iv;
    public static Server serv;
    public static  RC6.encryptionMode encMode;
    public Client(RC6.encryptionMode em, Server s){
        luc = new LUC(12);
        luc.setPublicKey();
        encMode = em;
        serv = s;
    }
    public Client(){
        luc = new LUC(12);
        luc.setPublicKey();
    }
    public void getSessionKey() {
        BigInteger[] encSessionKey = serv.getSessionKey(luc.getE(), luc.getN());
        sessionKey = (luc.decrypt(encSessionKey, luc.getE(), luc.getN(), luc.getP(), luc.getQ())).getBytes();
    }
    public void getIV() {
        BigInteger[] enciv = serv.getIV(luc.getE(), luc.getN());
        iv = (luc.decrypt(enciv, luc.getE(), luc.getN(), luc.getP(), luc.getQ())).getBytes();
    }
    public void encryptFile(File file) {
        try (InputStream is = new FileInputStream(file)){
            byte[] fileByte = new byte[(int)file.length()] ;
            int offset = 0;
            int numRead;
            while (offset < fileByte.length && (numRead = is.read(fileByte, offset, fileByte.length-offset)) >= 0) {
                offset += numRead;
            }
            fileByte = RC6.encrypt(fileByte, sessionKey, iv, encMode);
            serv.getFile(fileByte, file.getName());
        }
        catch (Exception e){
            System.err.println(e);
        }
    }

    public void decryptFile(String fileName, String fn) throws IOException {
        File file = serv.sendFile(fileName);
        InputStream is = new FileInputStream(file);
        byte[] fileByte = new byte[(int)file.length()] ;
        int offset = 0;
        int numRead;
        while (offset < fileByte.length && (numRead=is.read(fileByte, offset, fileByte.length-offset)) >= 0) {
            offset += numRead;
        }
        fileByte = RC6.decrypt(fileByte, sessionKey, iv, encMode);
        File file1 = new File("D:\\Программы\\IntelliJ IDEA Community Edition 2020.3.2\\CourseWorkCrypt\\src\\main\\resources\\client\\" + fn.substring(0, fn.length()-4));

        FileOutputStream os = new FileOutputStream(file1);
        os.write(fileByte);
        os.close();
    }
}

