/*
 * Copyright (c) 2015-2016, Octabase, Ltd. All Rights Reserved.
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

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class FNRUtils {
    private FNRUtils() {
        
    }
    
    final static void reverse(byte[] data) {
        byte swap;

        for(int i = 0; i < data.length / 2; i++) {
            swap = data[i];
            data[i] = data[data.length - i - 1];
            data[data.length - i - 1] = swap;
        }
    }
    
    public static byte[] createAes128KeyWithPBKDF2(String passphrase, String salt) throws GeneralSecurityException {
        if (passphrase == null || passphrase.length() == 0) {
            throw new IllegalArgumentException("The passphrase parameter cannot be null or empty.");
        }
        
        if (salt == null || salt.length() == 0) {
            throw new IllegalArgumentException("The salt parameter cannot be null or empty.");
        }

        return createAes128KeyWithPBKDF2(passphrase.getBytes(), salt.getBytes());
    }
    
    public static byte[] createAes128KeyWithPBKDF2(final byte[] passphrase, final byte[] salt) throws GeneralSecurityException {
        if (passphrase == null || passphrase.length == 0) {
            throw new IllegalArgumentException("The passphrase parameter cannot be null or empty.");
        }
        
        if (salt == null || salt.length == 0) {
            throw new IllegalArgumentException("The salt parameter cannot be null or empty.");
        }

        char[] passChars = new char[passphrase.length];

        for (int i = 0; i < passphrase.length; i++) {
            passChars[i] = (char) passphrase[i];
        }

        PBEKeySpec keySpec = new PBEKeySpec(passChars, salt, 1000, 128);
        Arrays.fill(passChars, (char) 0);

        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

        return keyFactory.generateSecret(keySpec).getEncoded();
    }
}
