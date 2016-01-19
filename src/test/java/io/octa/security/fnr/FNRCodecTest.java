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

import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.util.Date;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.BlockJUnit4ClassRunner;

@RunWith(BlockJUnit4ClassRunner.class)
public class FNRCodecTest extends FNRTestCase {
    @Test
    public void testBool() throws GeneralSecurityException {
        FNRKey key = new FNRKey(randomAesKey(), FNRCodec.BOOL.getRequiredKeyNumBits());
        FNRTweak tweak = key.generateTweak("alpha");

        for (boolean i: new boolean[] {true, false}) {
            boolean encrypted = FNRCipher.encrypt(FNRCodec.BOOL, key, tweak, i);
            
            boolean decrypted = FNRCipher.decrypt(FNRCodec.BOOL, key, tweak, encrypted);
            assertEquals(i, decrypted);
        }
    }

    @Test
    public void testByte() throws GeneralSecurityException {
        FNRKey key = new FNRKey(randomAesKey(), FNRCodec.BYTE.getRequiredKeyNumBits());
        FNRTweak tweak = key.generateTweak("alpha");

        for (byte i = Byte.MIN_VALUE; i < Byte.MAX_VALUE; i++) {
            byte encrypted = FNRCipher.encrypt(FNRCodec.BYTE, key, tweak, i);
            if (i < 0) assertEquals(true, encrypted < 0);
            if (i >= 0) assertEquals(true, encrypted >= 0);

            byte decrypted = FNRCipher.decrypt(FNRCodec.BYTE, key, tweak, encrypted);
            assertEquals(i, decrypted);
        }
    }

    @Test
    public void testByteNPSign() throws GeneralSecurityException {
        FNRKey key = new FNRKey(randomAesKey(), FNRCodec.BYTE_NP_SIGN.getRequiredKeyNumBits());
        FNRTweak tweak = key.generateTweak("alpha");

        for (byte i = Byte.MIN_VALUE; i < Byte.MAX_VALUE; i++) {
            byte encrypted = FNRCipher.encrypt(FNRCodec.BYTE_NP_SIGN, key, tweak, i);
            
            byte decrypted = FNRCipher.decrypt(FNRCodec.BYTE_NP_SIGN, key, tweak, encrypted);
            assertEquals(i, decrypted);
        }
    }

    @Test
    public void testShort() throws GeneralSecurityException {
        FNRKey key = new FNRKey(randomAesKey(), FNRCodec.SHORT.getRequiredKeyNumBits());
        FNRTweak tweak = key.generateTweak("alpha");

        for (short i = -5; i < 5; i++) {
            short encrypted = FNRCipher.encrypt(FNRCodec.SHORT, key, tweak, i);
            if (i < 0) assertEquals(true, encrypted < 0);
            if (i >= 0) assertEquals(true, encrypted >= 0);

            short decrypted = FNRCipher.decrypt(FNRCodec.SHORT, key, tweak, encrypted);
            assertEquals(i, decrypted);
        }
    }

    @Test
    public void testShortNPSign() throws GeneralSecurityException {
        FNRKey key = new FNRKey(randomAesKey(), FNRCodec.SHORT_NP_SIGN.getRequiredKeyNumBits());
        FNRTweak tweak = key.generateTweak("alpha");

        for (short i = -5; i < 5; i++) {
            short encrypted = FNRCipher.encrypt(FNRCodec.SHORT_NP_SIGN, key, tweak, i);
            
            short decrypted = FNRCipher.decrypt(FNRCodec.SHORT_NP_SIGN, key, tweak, encrypted);
            assertEquals(i, decrypted);
        }
    }

    @Test
    public void testChar() throws GeneralSecurityException {
        FNRKey key = new FNRKey(randomAesKey(), FNRCodec.CHAR.getRequiredKeyNumBits());
        FNRTweak tweak = key.generateTweak("alpha");

        for (char i = 0; i < 5; i++) {
            char encrypted = FNRCipher.encrypt(FNRCodec.CHAR, key, tweak, i);
            if (i < 0) assertEquals(true, encrypted < 0);
            if (i >= 0) assertEquals(true, encrypted >= 0);

            char decrypted = FNRCipher.decrypt(FNRCodec.CHAR, key, tweak, encrypted);
            assertEquals(i, decrypted);
        }
    }

    @Test
    public void testCharNPSign() throws GeneralSecurityException {
        FNRKey key = new FNRKey(randomAesKey(), FNRCodec.CHAR_NP_SIGN.getRequiredKeyNumBits());
        FNRTweak tweak = key.generateTweak("alpha");

        for (char i = 0; i < 5; i++) {
            char encrypted = FNRCipher.encrypt(FNRCodec.CHAR_NP_SIGN, key, tweak, i);
            
            char decrypted = FNRCipher.decrypt(FNRCodec.CHAR_NP_SIGN, key, tweak, encrypted);
            assertEquals(i, decrypted);
        }
    }

    @Test
    public void testInt() throws GeneralSecurityException {
        FNRKey key = new FNRKey(randomAesKey(), FNRCodec.INT.getRequiredKeyNumBits());
        FNRTweak tweak = key.generateTweak("alpha");

        for (int i = -5; i < 5; i++) {
            int encrypted = FNRCipher.encrypt(FNRCodec.INT, key, tweak, i);
            if (i < 0) assertEquals(true, encrypted < 0);
            if (i >= 0) assertEquals(true, encrypted >= 0);

            int decrypted = FNRCipher.decrypt(FNRCodec.INT, key, tweak, encrypted);
            assertEquals(i, decrypted);
        }
    }

    @Test
    public void testIntNPSign() throws GeneralSecurityException {
        FNRKey key = new FNRKey(randomAesKey(), FNRCodec.INT_NP_SIGN.getRequiredKeyNumBits());
        FNRTweak tweak = key.generateTweak("alpha");

        for (int i = -5; i < 5; i++) {
            int encrypted = FNRCipher.encrypt(FNRCodec.INT_NP_SIGN, key, tweak, i);
            
            int decrypted = FNRCipher.decrypt(FNRCodec.INT_NP_SIGN, key, tweak, encrypted);
            assertEquals(i, decrypted);
        }
    }

    @Test
    public void testFloat() throws GeneralSecurityException {
        FNRKey key = new FNRKey(randomAesKey(), FNRCodec.FLOAT.getRequiredKeyNumBits());
        FNRTweak tweak = key.generateTweak("alpha");

        for (float i = -5; i < 5; i += 0.25) {
            float encrypted = FNRCipher.encrypt(FNRCodec.FLOAT, key, tweak, i);
            if (i < 0) assertEquals(true, encrypted < 0);
            if (i >= 0) assertEquals(true, encrypted >= 0);

            float decrypted = FNRCipher.decrypt(FNRCodec.FLOAT, key, tweak, encrypted);
            assertEquals(i, decrypted);
        }
    }

    @Test
    public void testFloatNPSignExp() throws GeneralSecurityException {
        FNRKey key = new FNRKey(randomAesKey(), FNRCodec.FLOAT_NP_SIGN_EXP.getRequiredKeyNumBits());
        FNRTweak tweak = key.generateTweak("alpha");

        for (float i = -5; i < 5; i += 0.25) {
            float encrypted = FNRCipher.encrypt(FNRCodec.FLOAT_NP_SIGN_EXP, key, tweak, i);
            
            float decrypted = FNRCipher.decrypt(FNRCodec.FLOAT_NP_SIGN_EXP, key, tweak, encrypted);
            assertEquals(i, decrypted);
        }
    }

    @Test
    public void testLong() throws GeneralSecurityException {
        FNRKey key = new FNRKey(randomAesKey(), FNRCodec.LONG.getRequiredKeyNumBits());
        FNRTweak tweak = key.generateTweak("alpha");

        for (long i = -5; i < 5; i++) {
            long encrypted = FNRCipher.encrypt(FNRCodec.LONG, key, tweak, i);
            if (i < 0) assertEquals(true, encrypted < 0);
            if (i >= 0) assertEquals(true, encrypted >= 0);

            long decrypted = FNRCipher.decrypt(FNRCodec.LONG, key, tweak, encrypted);
            assertEquals(i, decrypted);
        }
    }

    @Test
    public void testLongNPSign() throws GeneralSecurityException {
        FNRKey key = new FNRKey(randomAesKey(), FNRCodec.LONG_NP_SIGN.getRequiredKeyNumBits());
        FNRTweak tweak = key.generateTweak("alpha");

        for (long i = -5; i < 5; i++) {
            long encrypted = FNRCipher.encrypt(FNRCodec.LONG_NP_SIGN, key, tweak, i);
            
            long decrypted = FNRCipher.decrypt(FNRCodec.LONG_NP_SIGN, key, tweak, encrypted);
            assertEquals(i, decrypted);
        }
    }

    @Test
    public void testDouble() throws GeneralSecurityException {
        FNRKey key = new FNRKey(randomAesKey(), FNRCodec.DOUBLE.getRequiredKeyNumBits());
        FNRTweak tweak = key.generateTweak("alpha");

        for (double i = -5; i < 5; i += 0.25) {
            double encrypted = FNRCipher.encrypt(FNRCodec.DOUBLE, key, tweak, i);
            if (i < 0) assertEquals(true, encrypted < 0);
            if (i >= 0) assertEquals(true, encrypted >= 0);

            double decrypted = FNRCipher.decrypt(FNRCodec.DOUBLE, key, tweak, encrypted);
            assertEquals(i, decrypted);
        }
    }

    @Test
    public void testDoubleNPSignExp() throws GeneralSecurityException {
        FNRKey key = new FNRKey(randomAesKey(), FNRCodec.DOUBLE_NP_SIGN_EXP.getRequiredKeyNumBits());
        FNRTweak tweak = key.generateTweak("alpha");

        for (double i = -5; i < 5; i += 0.25) {
            double encrypted = FNRCipher.encrypt(FNRCodec.DOUBLE_NP_SIGN_EXP, key, tweak, i);
            
            double decrypted = FNRCipher.decrypt(FNRCodec.DOUBLE_NP_SIGN_EXP, key, tweak, encrypted);
            assertEquals(i, decrypted);
        }
    }

    @Test
    public void testIPv4() throws GeneralSecurityException, UnknownHostException {
        FNRKey key = new FNRKey(randomAesKey(), FNRCodec.IPV4.getRequiredKeyNumBits());
        FNRTweak tweak = key.generateTweak("alpha");

        for (Inet4Address i: new Inet4Address[] { (Inet4Address) Inet4Address.getByName("192.168.1.1"), (Inet4Address) Inet4Address.getByName("212.11.0.2") }) {
            Inet4Address encrypted = FNRCipher.encrypt(FNRCodec.IPV4, key, tweak, i);
            
            Inet4Address decrypted = FNRCipher.decrypt(FNRCodec.IPV4, key, tweak, encrypted);
            assertEquals(i, decrypted);
        }
    }

    @Test
    public void testIPv6() throws GeneralSecurityException, UnknownHostException {
        FNRKey key = new FNRKey(randomAesKey(), FNRCodec.IPV6.getRequiredKeyNumBits());
        FNRTweak tweak = key.generateTweak("alpha");

        for (Inet6Address i: new Inet6Address[] { (Inet6Address) Inet6Address.getByName("2001:cdba:0000:0000:0000:0000:3257:9652"), (Inet6Address) Inet6Address.getByName("2607:f0d0:1002:0051:0000:0000:0000:0004") }) {
            Inet6Address encrypted = FNRCipher.encrypt(FNRCodec.IPV6, key, tweak, i);
  
            Inet6Address decrypted = FNRCipher.decrypt(FNRCodec.IPV6, key, tweak, encrypted);
            assertEquals(i, decrypted);
        }
    }

    @Test
    @SuppressWarnings("deprecation")
    public void testDate() throws GeneralSecurityException {
        FNRKey key = new FNRKey(randomAesKey(), FNRCodec.DATE.getRequiredKeyNumBits());
        FNRTweak tweak = key.generateTweak("alpha");

        for (Date i: new Date[] { new Date(), new Date("Sun Mar 11 22:36:00 1990") }) {
            Date encrypted = FNRCipher.encrypt(FNRCodec.DATE, key, tweak, i);
  
            Date decrypted = FNRCipher.decrypt(FNRCodec.DATE, key, tweak, encrypted);
            assertEquals(i, decrypted);
        }
    }

    @Test
    public void testBigInteger() throws GeneralSecurityException {
        FNRKey key = new FNRKey(randomAesKey(), FNRCodec.BIGINT_128.getRequiredKeyNumBits());
        FNRTweak tweak = key.generateTweak("alpha");

        for (BigInteger i: new BigInteger[] { new BigInteger("-5615213213213656"), new BigInteger("0"), new BigInteger("343243") }) {
            BigInteger encrypted = FNRCipher.encrypt(FNRCodec.BIGINT_128, key, tweak, i);
            if (i.signum() == -1) assertEquals(-1, encrypted.signum());
            if (i.signum() >= 0) assertEquals(true, encrypted.signum() >= 0);
  
            BigInteger decrypted = FNRCipher.decrypt(FNRCodec.BIGINT_128, key, tweak, encrypted);
            assertEquals(i, decrypted);
        }
    }

    @Test
    public void testBigIntegerNPSign() throws GeneralSecurityException {
        FNRKey key = new FNRKey(randomAesKey(), FNRCodec.BIGINT_128_NP_SIGN.getRequiredKeyNumBits());
        FNRTweak tweak = key.generateTweak("alpha");

        for (BigInteger i: new BigInteger[] { new BigInteger("-5615213213213656"), new BigInteger("0"), new BigInteger("343243") }) {
            BigInteger encrypted = FNRCipher.encrypt(FNRCodec.BIGINT_128_NP_SIGN, key, tweak, i);

            BigInteger decrypted = FNRCipher.decrypt(FNRCodec.BIGINT_128_NP_SIGN, key, tweak, encrypted);
            assertEquals(i, decrypted);
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testBigIntegerEncodeWrongData() throws GeneralSecurityException {
        FNRCodec.BIGINT_128.encode(new BigInteger("2").pow(128));
    }


    @Test(expected = IllegalArgumentException.class)
    public void testBigIntegerDecodeWrongData() throws GeneralSecurityException {
        FNRCodec.BIGINT_128.decode(new byte[17]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testBigIntegerNPWrongData() throws GeneralSecurityException {
        FNRCodec.BIGINT_128_NP_SIGN.decode(new byte[17]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testIpv4WrongData() throws GeneralSecurityException {
        FNRCodec.IPV4.decode(new byte[2]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testIpv6WrongData() throws GeneralSecurityException {
        FNRCodec.IPV6.decode(new byte[2]);
    }
}
