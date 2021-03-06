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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Random;

import org.junit.Assume;
import org.junit.AssumptionViolatedException;
import org.junit.Test;
import org.junit.runner.Description;
import org.junit.runner.RunWith;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.InitializationError;

import com.cisco.fnr.FNR;

@RunWith(FNRCipherTest.FNRCipherTestRunner.class)
public class FNRCipherTest extends FNRTestCase {
    public static class FNRCipherTestRunner extends BlockJUnit4ClassRunner {
        public FNRCipherTestRunner(Class<?> klass) throws InitializationError {
            super(klass);
        }

        @Override
        protected void runChild(final FrameworkMethod method, RunNotifier notifier) {
            Description description = describeChild(method);
            if (isIgnored(method)) {
                notifier.fireTestIgnored(description);
            } else {
                try {
                    runLeaf(methodBlock(method), description, notifier);
                } catch (AssumptionViolatedException ex) {
                    notifier.fireTestIgnored(description);
                }
            }
        }
    }
    
    @Test
    public void testBitLengths() throws GeneralSecurityException {
        byte test[] = new byte[128 / 8];

        for (int i = 0; i < 128; i++) {
            Arrays.fill(test, (byte) 0x00);

            int j = 0;
            for (; j < (i / 8); j++) {
                test[j] = (byte) 0xFF;
            }

            test[j] = (byte) (0xFF >> (7 - (i % 8)));

            FNRKey key = new FNRKey(randomAesKey(), i + 1);
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
    
    @Test
    public void fixCoberturaCoverage() throws GeneralSecurityException, IllegalArgumentException, InstantiationException, IllegalAccessException, InvocationTargetException {
        Constructor<?> privateConstructor = FNRCipher.class.getDeclaredConstructors()[0];
        privateConstructor.setAccessible(true);
        privateConstructor.newInstance((Object[]) null);
    }
    
    @Test(expected = NullPointerException.class)
    public void testCodecOperateNullCodecGuard() throws GeneralSecurityException {
        FNRKey key = new FNRKey(randomAesKey(), 2);
        FNRTweak tweak = key.generateTweak("test");

        FNRCipher.encrypt(null, key, tweak, new Object());
    }
    
    @Test(expected = NullPointerException.class)
    public void testCodecOperateNullInputGuard() throws GeneralSecurityException {
        FNRKey key = new FNRKey(randomAesKey(), 2);
        FNRTweak tweak = key.generateTweak("test");

        FNRCipher.encrypt(FNRCodec.BOOL, key, tweak, null);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testCodecOperateWrongKeySizeGuard() throws GeneralSecurityException {
        FNRKey key = new FNRKey(randomAesKey(), 2);
        FNRTweak tweak = key.generateTweak("test");

        FNRCipher.encrypt(FNRCodec.BOOL, key, tweak, true);
    }
    
    @Test(expected = NullPointerException.class)
    public void testOperateNullKeyGuard() throws GeneralSecurityException {
        FNRKey key = new FNRKey(randomAesKey(), 2);
        FNRTweak tweak = key.generateTweak("test");
        
        FNRCipher.encrypt(null, tweak, new byte[0]);
    }
    
    @Test(expected = NullPointerException.class)
    public void testCodecOperateNullTweakGuard() throws GeneralSecurityException {
        FNRKey key = new FNRKey(randomAesKey(), 2);

        FNRCipher.encrypt(key, null, new byte[0]);
    }
    
    @Test(expected = NullPointerException.class)
    public void testOperateNullInputGuard() throws GeneralSecurityException {
        FNRKey key = new FNRKey(randomAesKey(), 1);
        FNRTweak tweak = key.generateTweak("test");

        FNRCipher.encrypt(key, tweak, null);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testOperateWrongInputGuard() throws GeneralSecurityException {
        FNRKey key = new FNRKey(randomAesKey(), 9);
        FNRTweak tweak = key.generateTweak("test");

        FNRCipher.encrypt(key, tweak, new byte[1]);
    }

    @Test
    public void testNativeCompability() throws GeneralSecurityException {
        Assume.assumeTrue(System.getProperty("os.name").toLowerCase().startsWith("linux") && System.getProperty("os.arch").contains("64"));

        Random rand = new Random();
        
        byte[] aes128Key = randomAesKey();

        String tweakValue = "tweak";
        
        byte test[] = new byte[128 / 8];
        
        for (int i = 0; i < 128; i++) {
            Arrays.fill(test, (byte) 0x00);

            int j = 0;
            for (; j < (i / 8); j++) {
                test[j] = (byte) rand.nextInt(255);
            }

            test[j] = (byte) (0xFF >> (7 - (i % 8)));

            FNRKey key = new FNRKey(aes128Key, i + 1, false);
            FNRTweak tweak = key.generateTweak(tweakValue);
            
            FNRKey keyBuiltIn = new FNRKey(aes128Key, i + 1, true);
            FNRTweak tweakBuiltIn = keyBuiltIn.generateTweak(tweakValue);

            assertTrue(Arrays.equals(tweak.get(), tweakBuiltIn.get()));

            byte encrypted[] = FNRCipher.encrypt(key, tweak, test);
            byte encryptedBuiltIn[] = FNRCipher.encrypt(keyBuiltIn, tweakBuiltIn, test);

            assertTrue(Arrays.equals(encrypted, encryptedBuiltIn));

            FNR jnaCipher = new FNR(aes128Key, tweakValue, i + 1);
            byte encryptedJNA[] = jnaCipher.encrypt(test);

            assertTrue(Arrays.equals(encrypted, encryptedJNA));
        }
    }
}
