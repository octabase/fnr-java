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

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

class PWIPStream {
    private Key key;
    private int numBits;
    private int count;
    private int index;
    private int bitCount;
    private byte buffer[] = new byte[FNRCipher.BLOCK_SIZE];

    PWIPStream(Key key, int numBits) {
        this.key = key;
        this.numBits = (byte) numBits;
        this.count = 0;
        this.index = FNRCipher.BLOCK_SIZE;
    }
    
    void erase() {
        this.key = null;
        this.numBits = 0;
        this.count = 0;
        this.index = 0;
        this.bitCount = 0;
        Arrays.fill(this.buffer, (byte) 0);
    }
    
    byte nextBit() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (index == FNRCipher.BLOCK_SIZE) {
            byte block[] = new byte[FNRCipher.BLOCK_SIZE];
            
            long newCount = count++;
            block[0] = (byte) (newCount & 0xFF);
            block[1] = (byte) (newCount >> 8 & 0xFF);
            block[2] = (byte) (newCount >> 16 & 0xFF);
            block[3] = (byte) (newCount >> 24 & 0xFF);

            block[FNRCipher.BLOCK_SIZE - 2] = (byte) this.numBits;
            block[FNRCipher.BLOCK_SIZE - 1] = FNRCipher.RND_MARKER;

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = cipher.doFinal(block);
            Arrays.fill(block, (byte) 0);

            System.arraycopy(encrypted, 0, this.buffer, 0, this.buffer.length);
            Arrays.fill(encrypted, (byte) 0);

            index = 0;
            bitCount = 0;
        }

        byte bit = (byte) ((buffer[index] >> bitCount) & 0x01);

        bitCount++;
        if (bitCount == 8) {
            index++;
            bitCount = 0;
        }

        return bit;
    }

    int nextBits(int n) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        int result = 0;

        for (int i = 0; i < n; i++) {
            result += nextBit() << i;
        }
        
        return result;
    }
    
    int nextBitsNotAllZero(byte[] bits, int nBits) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        if (nBits == 1) {
            bits[0] = 1;
            return 0;
        }

        int firstNonZero = -1;
        do {
            for (int i = 0; i < nBits; i++) {
                bits[i] = (byte) nextBit();
                if (firstNonZero < 0 && bits[i] != 0) {
                    firstNonZero = i;
                }
            }
        } while (firstNonZero < 0);

        return firstNonZero;
    }
}
