/*
 * Copyright (c) 2015-2016, Octabase, Inc. All Rights Reserved.
 *
 * FNR Cipher is a Java implementation for Flexible Naor and Reingold encryption scheme.
 * 
 * FNR represents "Flexible Naor and Reingold" 
 * 
 * FNR is a small domain block cipher to encrypt small domain
 * objects ( < 128 bits ) like IPv4, MAC, Credit Card numbers etc.
 * 
 * FNR is designed by Sashank Dara (sadara@cisco.com), Scott Fluhrer (sfluhrer@cisco.com)
 * 
 * Java implementation was written by Mehmet Gurevin (mehmet.gurevin@octabase.com)
 * 
 * Licensed under the GNU Lesser General Public License, Version 2.1 (the "License");
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * http://www.gnu.org/licenses/old-licenses/lgpl-2.1.txt
 */

package io.octa.security.fnr;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class FNRKey {
    public final static boolean DEFAULT_USE_BUILT_IN_AES_ENCRYPTION = false;

    private final int fullBytes;
    private final byte finalMask;
    private final int fullElements;
    private final byte finalElementMask;
    private final int numBits;
    private final int redIndex;
    private final int greenIndex;
    private final byte[] vector;
    private final Key aesKey;
    private final int elementsPerRow;
    private final int[][] builtInAesKey;

    public FNRKey(final byte[] aes128Key, int numBits) throws GeneralSecurityException {
        this(aes128Key, numBits, DEFAULT_USE_BUILT_IN_AES_ENCRYPTION);
    }

    public FNRKey(final byte[] aes128Key, int numBits, boolean useBuiltInAesEncryption) throws GeneralSecurityException {
        if (aes128Key == null) {
            throw new NullPointerException("The aes128Key parameter cannot be null");
        }

        if (aes128Key.length != 16) {
            throw new IllegalArgumentException("The aes128Key parameter value must be 128 bit (16 bytes)");
        }

        if (numBits < 1 || numBits > 128) {
            throw new IllegalArgumentException("The numBits parameter value must be range of 1 to 128");
        }

        this.elementsPerRow = countOfElementsPerRow(numBits);
        this.fullBytes = (numBits - 1) / 8;
        this.fullElements = this.fullBytes;
        this.finalMask = (byte) (0xFF & ((1 << ((numBits + 7) % 8 + 1)) - 1));
        this.finalElementMask = this.finalMask;
        this.numBits = numBits;
        this.vector = new byte[2 * (this.elementsPerRow * (numBits + 1))];
        this.redIndex = 0;
        this.greenIndex = this.elementsPerRow * (numBits + 1);

        if (useBuiltInAesEncryption) {
            this.aesKey = null;
            this.builtInAesKey = AES128Encryption.generateEncryptionKey(aes128Key);
        } else {
            this.aesKey = new SecretKeySpec(aes128Key, "AES");
            this.builtInAesKey = null;
        }

        this.expandRedGreen();
    }

    public FNRTweak generateTweak(String tweakString) throws GeneralSecurityException {
        if (tweakString == null) {
            throw new NullPointerException("The tweakString parameter cannot be null");
        }

        return generateTweak(tweakString.getBytes());
    }

    public FNRTweak generateTweak(final byte tweakBytes[]) throws GeneralSecurityException {
        byte block[] = new byte[FNRCipher.BLOCK_SIZE];

        int tweakLen = tweakBytes.length;
        if (tweakLen == 0) {
            throw new IllegalArgumentException("The tweakBytes parameter value cannot be empty");
        }

        block[0] = (byte) (tweakLen >> 0 & 0xFF);
        block[1] = (byte) (tweakLen >> 8 & 0xFF);
        block[2] = (byte) (tweakLen >> 16 & 0xFF);
        block[3] = (byte) (tweakLen >> 24 & 0xFF);
        
        block[4] = (byte) this.numBits;
        
        Cipher cipher = null;
        if (builtInAesKey == null) {
            cipher = Cipher.getInstance("AES/ECB/NoPadding");
        }

        int n = 5;
        int i = 0;
        do {
            for (; n < FNRCipher.BLOCK_SIZE - 1 && tweakLen > 0; n++) {
                block[n] ^= tweakBytes[i++];
                tweakLen--;
            }

            block[FNRCipher.BLOCK_SIZE - 1] = FNRCipher.TWEAK_MARKER;

            if (builtInAesKey != null) {
                AES128Encryption.encrypt(builtInAesKey, block);
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, this.aesKey);
                byte[] encrypted = cipher.doFinal(block);
                System.arraycopy(encrypted, 0, block, 0, block.length);
                Arrays.fill(encrypted, (byte) 0);
            };
            
            n = 0;
        } while (tweakLen > 0);
        
        byte generated[] = new byte[FNRCipher.BLOCK_SIZE - 1];
        
        System.arraycopy(block, 0, generated, 0, FNRCipher.BLOCK_SIZE - 1);

        return new FNRTweak(generated);
    }

    private void multiplyGenMatrix(int n, int a, GenMatrix sub) {
        int elementsPerRow = countOfElementsPerRow(n);

        int aRow = elementsPerRow * (sub.a + 1);
        int bRow = elementsPerRow * (sub.b + 1);

        if (sub.type == GMT_SWAP) {
            for (int i = 0; i < elementsPerRow; i++, aRow++, bRow++) {
                byte t = vector[a + aRow]; 
                vector[a + aRow] = vector[a + bRow];
                vector[a + bRow] = t;
             }
        } else if (sub.type == GMT_XOR) {
            for (int i = 0; i < elementsPerRow; i++, aRow++, bRow++) {
                vector[a + bRow] ^= vector[a + aRow];
             }
        }
    }

    private void expandRedGreen() throws GeneralSecurityException {
        PWIPStream pwipStream = new PWIPStream(this.numBits);

        GenMatrix genMatrix[] = new GenMatrix[(this.numBits * (this.numBits - 1)) + 1];
        byte bits[] = new byte[128];

        for (int i = 0; i < genMatrix.length; i++) {
            genMatrix[i] = new GenMatrix();
        }

        int index = 0;
        
        for (int i = 0; i < this.numBits; i++) {
            int firstNonZero = pwipStream.nextBitsNotAllZero(this, bits, this.numBits - i);
            
            if (firstNonZero > 0) {
                genMatrix[index].type = GMT_SWAP;
                genMatrix[index].a = (byte) i;
                genMatrix[index].b = (byte) (i + firstNonZero);
                index++;
                
                bits[firstNonZero] = 0;
            }
            
            for (int j = 1; j < (this.numBits - i); j++) {
                if (bits[j] != 0) {
                    genMatrix[index].type = GMT_XOR;
                    genMatrix[index].a = (byte) i;
                    genMatrix[index].b = (byte) (i + j);
                    index++;
                }
            }       
            
            for (int j = 0; j < i; j++) {
                if (pwipStream.nextBit(this) != 0) {
                    genMatrix[index].type = GMT_XOR;
                    genMatrix[index].a = (byte) i;
                    genMatrix[index].b = (byte) j;
                    
                    index++;
                }
            }
        }

        Arrays.fill(bits, (byte) 0);
        Arrays.fill(this.vector, this.redIndex, this.redIndex + (this.numBits * this.elementsPerRow), (byte) 0);
        Arrays.fill(this.vector, this.greenIndex, this.greenIndex + (this.numBits * this.elementsPerRow), (byte) 0);

        byte bit = 0;
        int column = -1;
        
        for (int i = 0; i < this.numBits; i++) {
            if (i % 8 == 0) {
                bit = 1;
                column++;
            }
            
            this.vector[this.redIndex + this.elementsPerRow + (i * this.elementsPerRow) + column] = bit;
            this.vector[this.greenIndex + this.elementsPerRow + (i * this.elementsPerRow) + column] = bit;
            bit <<= 1;
        }

        for (int i = index; i > 0; i--) {
            multiplyGenMatrix(this.numBits, this.redIndex, genMatrix[i - 1]);
        }
        
        for (int i = 0; i < index; i++) {
            multiplyGenMatrix(this.numBits, this.greenIndex, genMatrix[i]);
        }

        for (GenMatrix m: genMatrix) {
            m.a = 0;
            m.b = 0;
            m.type = 0;
        }

        column = -1;
        for (int i = 0; i < this.numBits; i += 8) {
            int bitsThisTime = this.numBits - i;
            
            if (bitsThisTime > 8) {
                bitsThisTime = 8;
            }

            this.vector[this.redIndex + (i / 8)] = (byte) pwipStream.nextBits(this, bitsThisTime);
        }

        Arrays.fill(this.vector, this.greenIndex, this.greenIndex + this.elementsPerRow, (byte) 0);

        pwip(this.greenIndex, this.vector, this.redIndex, this.vector, this.greenIndex, this.vector);

        pwipStream.erase();
    }

    void pwip(int m, final byte mData[], int in, final byte inData[], int out, byte outData[]) {
        int elementsPerRow = fullElements;
        
        int i = 0;
        
        for (; i < elementsPerRow; i++) {
            outData[out + i] = mData[m++];
        }

        outData[out + i] = (byte) ((outData[out + i] & ~this.finalElementMask) | mData[m++]);

        byte a = 0;
        for (i = 0; i < this.numBits; i++) {
            if (i % FNRCipher.BITS_PER_ELEMENT == 0) {
                a = inData[in++];
            }

            byte mask = (byte) -(a & 1);
            a >>= 1;

            for (int j = 0; j <= elementsPerRow; j++) {
                outData[out + j] ^= mask & mData[m++];
            }
        }
    }

    int getFullBytes() {
        return fullBytes;
    }

    byte getFinalMask() {
        return finalMask;
    }
    public int getNumBits() {
        return numBits;
    }

    Key getAesKey() {
        return aesKey;
    }

    int[][] getBuiltInAesKey() {
        return builtInAesKey;
    }

    int getRedIndex() {
        return redIndex;
    }

    int getGreenIndex() {
        return greenIndex;
    }

    byte[] getVector() {
        return vector;
    }

    private final static int GMT_SWAP = 1;
    private final static int GMT_XOR = 2;
    
    private static class GenMatrix {
        int type;
        byte a;
        byte b;
    };

    private static int countOfElementsPerRow(int n) {
        return (n + FNRCipher.BITS_PER_ELEMENT - 1) / FNRCipher.BITS_PER_ELEMENT;
    }
}
