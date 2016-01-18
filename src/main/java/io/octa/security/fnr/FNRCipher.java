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
import java.util.Arrays;

import javax.crypto.Cipher;

public class FNRCipher {
    final static int N_ROUND = 7;
    final static int BITS_PER_ELEMENT = 8;
    final static int BLOCK_SIZE = 16;
    final static byte RND_MARKER = (byte) 0xC0;
    final static byte TWEAK_MARKER = (byte) 0xFF;
    final static byte[] ROUND_CONST = {0x00, 0x03, 0x0c, 0x0f, 0x30, 0x33, 0x3c};

    private FNRCipher() {
        
    }

    public static <T> T encrypt(FNRCodec<T> codec, FNRKey key, FNRTweak tweak, T input) throws GeneralSecurityException {
        return codecOperate(codec, key, tweak, input, true);
    }

    public static <T> T decrypt(FNRCodec<T> codec, FNRKey key, FNRTweak tweak, T input) throws GeneralSecurityException {
        return codecOperate(codec, key, tweak, input, false);
    }
    
    private static <T> T codecOperate(FNRCodec<T> codec, FNRKey key, FNRTweak tweak, T input, boolean enc) throws GeneralSecurityException {
        if (codec == null) {
            throw new NullPointerException("The codec parameter cannot be null.");
        }

        if (key == null) {
            throw new NullPointerException("The key parameter cannot be null.");
        }

        if (tweak == null) {
            throw new NullPointerException("The tweak parameter cannot be null.");
        }

        if (input == null) {
            throw new NullPointerException("The input parameter cannot be null.");
        }

        if (codec.getRequiredKeyNumBits() != key.getNumBits()) {
            throw new IllegalArgumentException("The number of bits of key(" + key.getNumBits() + ") are not compatible with selected codec(" + codec.getRequiredKeyNumBits() + ").");
        }
        
        return codec.decode(enc ? encrypt(key, tweak, codec.encode(input)) : decrypt(key, tweak, codec.encode(input)));
    }

    public static byte[] encrypt(FNRKey key, FNRTweak tweak, byte[] input) throws GeneralSecurityException {
        return operate(key, tweak, input, 0, 1);
    }

    public static byte[] decrypt(FNRKey key, FNRTweak tweak, byte[] input) throws GeneralSecurityException {
        return operate(key, tweak, input, N_ROUND - 1, -1);
    }

    private static byte[] operate(FNRKey key, FNRTweak tweak, final byte[] input, int round, int roundInc) throws GeneralSecurityException {
        if (key == null) {
            throw new NullPointerException("The key parameter cannot be null.");
        }

        if (tweak == null) {
            throw new NullPointerException("The tweak parameter cannot be null.");
        }

        if (input == null) {
            throw new NullPointerException("The input parameter cannot be null.");
        }

        if (input.length * 8 < key.getNumBits()) {
            throw new IllegalArgumentException("The number of bits of input(" + input.length * 8 + ") are not enough for the selected key(" + key.getNumBits() + ").");
        }
        
        byte[] out = new byte[input.length];
        System.arraycopy(input, 0, out, 0, input.length);

        byte[] text = new byte[BLOCK_SIZE];

        key.pwip(key.getRedIndex(), key.getVector(), 0, input, 0, text);

        int i;
        byte block[] = new byte[BLOCK_SIZE];

        byte mask = 0x55;
        
        Cipher cipher = null;
        if (key.getBuiltInAesKey() == null) {
            cipher = Cipher.getInstance("AES/ECB/NoPadding");
        }

        for (i = 0; i < N_ROUND; i++, round += roundInc) {
            System.arraycopy(tweak.get(), 0, block, 0, BLOCK_SIZE - 1);

            block[BLOCK_SIZE-1] = ROUND_CONST[round];

            int j = 0;
            for (; j < key.getFullBytes(); j++) {
                block[j] ^= text[j] & mask;
            }

            block[j] ^= text[j] & mask & key.getFinalMask();

            if (key.getBuiltInAesKey() != null) {
                AES128Encryption.encrypt(key.getBuiltInAesKey(), block);
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, key.getAesKey());
                byte[] encrypted = cipher.doFinal(block);
                
                System.arraycopy(encrypted, 0, block, 0, block.length);
                Arrays.fill(encrypted, (byte) 0);
            }

            mask ^= 0xFF;
            
            for (j = 0; j <= key.getFullBytes(); j++) {
                text[j] ^= block[j] & mask;
            }
        }
        Arrays.fill(block, (byte) 0);

        key.pwip(key.getGreenIndex(), key.getVector(), 0, text, 0, out);
        Arrays.fill(text, (byte) 0);
        
        return out;
    }
}
