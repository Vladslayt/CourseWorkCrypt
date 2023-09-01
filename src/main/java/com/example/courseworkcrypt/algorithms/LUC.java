package com.example.courseworkcrypt.algorithms;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Random;


public class LUC {
    private BigInteger p;
    private BigInteger q;
    private BigInteger N;
    private BigInteger e;
    private BigInteger d;
    private final int maxLength; //bit

    public LUC(int maxLength){
        this.maxLength = maxLength;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getQ() {
        return q;
    }

    public BigInteger getN() {
        return N;
    }

    public BigInteger getE() {
        return e;
    }

    public void setPublicKey(){
        Random r = new Random();
        p = BigInteger.probablePrime(maxLength, r);
        do{
            q = BigInteger.probablePrime(maxLength, r);
        }while(q.compareTo(p)==0);
        N = p.multiply(q);
        BigInteger t = p.subtract(BigInteger.valueOf(1)).multiply(p.add(BigInteger.valueOf(1))).multiply(q.subtract(BigInteger.valueOf(1))).multiply(q.add(BigInteger.valueOf(1)));
        e = BigInteger.probablePrime(maxLength, r);
        while(calcFPB(t,e).compareTo(BigInteger.valueOf(1)) != 0) {
            e = e.add(BigInteger.valueOf(1));
        }
    }

    public void setPrivateKey(BigInteger c, BigInteger e, BigInteger p, BigInteger q) {
        BigInteger det = c.multiply(c).subtract(BigInteger.valueOf(4)); // m*m-4
        BigInteger num1 = p.subtract((legendre(det, p)));
        BigInteger num2 = q.subtract((legendre(det, q)));
        BigInteger sn = calcKPK(num1, num2);
        d = modInverse(e, sn);
    }

    private BigInteger modInverse(BigInteger a, BigInteger m) {
        //Time Complexity: O(Log m)
        BigInteger m0 = m;
        BigInteger y = BigInteger.valueOf(0);
        BigInteger x = BigInteger.valueOf(1);

        if (m.compareTo(BigInteger.valueOf(1))==0) {
            return BigInteger.valueOf(0);
        }
        while (a.compareTo(BigInteger.valueOf(1)) > 0) {
            // q is quotient
            BigInteger q = a.divide(m);
            // t is temp
            BigInteger t = m;

            // m is remainder now, process
            // same as Euclid's algo
            m = a.mod(m);
            a = t;
            t = y;

            // Update x and y
            y = x.subtract(q.multiply(y));
            x = t;
        }

        // Make x positive
        if (x.compareTo(BigInteger.valueOf(0)) < 0) {
            x = x.add(m0);
        }
        return x;
    }

    public BigInteger calcFPB(BigInteger a, BigInteger b){
        BigInteger r;
        while(b.compareTo(BigInteger.valueOf(0)) != 0){
            r = a.mod(b);
            a = b;
            b = r;
        }
        return a;
    }

    public BigInteger calcKPK(BigInteger a, BigInteger b){
        return  (a.multiply(b)).divide(calcFPB(a, b));
    }

    private BigInteger legendre(BigInteger a, BigInteger p){
        if (a.equals(BigInteger.valueOf(0))){
            return BigInteger.valueOf(0);
        }
        if (a.equals(BigInteger.valueOf(1))){
            return BigInteger.valueOf(1);
        }
        BigInteger result;
        if (a.mod(BigInteger.valueOf(2)).equals(BigInteger.valueOf(0))){ //if an even
            result = legendre(a.divide(BigInteger.valueOf(2)), p);
            //if (((p * p - 1) & 8) != 0){
            if (p.multiply(p).subtract(BigInteger.valueOf(1)).and(BigInteger.valueOf(8)).compareTo(BigInteger.valueOf(0)) != 0){
                result = result.negate();
            }
        }
        else{
            result = legendre(p.mod(a), a);
            //if (((a - 1) * (p - 1) & 4) != 0){
            if (a.subtract(BigInteger.valueOf(1)).multiply(p.subtract(BigInteger.valueOf(1))).and(BigInteger.valueOf(4)).compareTo(BigInteger.valueOf(0)) != 0){
                result = result.negate();
            }
        }
        return result;
    }

    public BigInteger[] encrypt(byte[] m, BigInteger e, BigInteger N){
        BigInteger M;
        BigInteger[] C = new BigInteger[m.length/2];
        for (int a=0;a<m.length;a+=2){
            M = new BigInteger(String.valueOf((m[a]&0xFF)*256 + (m[a+1]&0xFF)));
            BigInteger Vnow;
            BigInteger Vnmin2 = BigInteger.valueOf(2);
            BigInteger Vnmin1 = M;
            for (int i = 2; i < e.intValue(); i++){
                Vnow = (M.multiply(Vnmin1).subtract(Vnmin2)).mod(N); //Ve[i] = (M * Ve[i - 1] - Ve[i - 2]) % N;
                Vnmin2 = Vnmin1;
                Vnmin1 = Vnow;
            }
            // int i == e
            C[a/2] = (M.multiply(Vnmin1).subtract(Vnmin2)).mod(N);
        }
        return C;
    }

    public String decrypt(BigInteger[] c, BigInteger e, BigInteger N, BigInteger p, BigInteger q) {
        StringBuilder M = new StringBuilder();
        BigInteger C;
        for (BigInteger bigInteger : c) {
            C = new BigInteger(String.valueOf(bigInteger));
            setPrivateKey(bigInteger, e, p, q);
            BigInteger Vnow;
            BigInteger Vnmin2 = BigInteger.valueOf(2);
            BigInteger Vnmin1 = C;
            for (int i = 2; i < d.intValue(); i++) {
                Vnow = (C.multiply(Vnmin1).subtract(Vnmin2)).mod(N); //Ve[i] = (C * Ve[i - 1] - Ve[i - 2]) % N;
                Vnmin2 = Vnmin1;
                Vnmin1 = Vnow;
            }
            Vnow = (C.multiply(Vnmin1).subtract(Vnmin2)).mod(N);
            byte[] z = {(byte) (Vnow.divide(BigInteger.valueOf(256)).byteValue() & 0xFF), (byte) (Vnow.mod(BigInteger.valueOf(256)).byteValue() & 0xFF)};
            M.append(new String(z, StandardCharsets.UTF_16BE));
        }
        return M.toString();
    }

    /*public String bigIntToString(BigInteger[] input){
        StringBuilder out = new StringBuilder();
        for (BigInteger bigInteger : input) {
            out.append(bigInteger).append(":");
        }
        return out.toString();

    }

    public BigInteger[] stringToBigInt(String text){
        String[] array = text.split(":");
        BigInteger[] out = new BigInteger[array.length];
        for (int i=0;i<array.length;i++){
            out[i] = new BigInteger(array[i]);
        }
        return out;
    }

    public int getBitDif(){
        return this.sum;
    }



    public static int countBinary(int n){
        int count = 0;
        while (n > 0){
            count = count + 1;
            n = n & (n-1);
        }
        return count;
    }

    public void print(){
        System.out.println("p = " + p);
        System.out.println("q = " + q);
        System.out.println("N = " + N);
        System.out.println("t = " + t);
        System.out.println("e = " + e);
        System.out.println("d = " + d);
        System.out.println("Sn = " + Sn);

    }*/

}
