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

public class FNRCipherTest extends FNRTestCase {
    public void testBitLengths() throws GeneralSecurityException {
        byte test[] = new byte[128 / 8];
        
        for (int i = 0; i < 128; i++) {
            Arrays.fill(test, (byte) 0x00);

            int j = 0;
            for (; j < (i / 8); j++) {
                test[j] = (byte) 0xFF;
            }

            test[j] = (byte) (0xFF >> (7 - (i % 8)));

            FNRKey key = generateKey(i + 1);
            FNRTweak tweak = key.generateTweak("alpha");
            
            byte encrypted[] = FNRCipher.encrypt(key, tweak, test);
            
            assertEquals(test.length, encrypted.length);

            byte bitTest[] = new byte[encrypted.length];
            System.arraycopy(encrypted, 0, bitTest, 0, encrypted.length);
            for (j = 0; j < test.length; j++) {
                bitTest[j] |= test[j];
            }

            assertTrue(Arrays.equals(bitTest, test));

            byte decrypted[] = FNRCipher.decrypt(key, tweak, encrypted);
            assertEquals(encrypted.length, decrypted.length);

            assertTrue(Arrays.equals(test, decrypted));
        }
    }
}