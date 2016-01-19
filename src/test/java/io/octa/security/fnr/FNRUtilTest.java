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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.BlockJUnit4ClassRunner;

@RunWith(BlockJUnit4ClassRunner.class)
public class FNRUtilTest extends FNRTestCase {
    @Test
    public void testReverse() throws GeneralSecurityException {
        byte[] test = new byte[] {1, 2, 3};
        byte[] expected = new byte[] {3, 2, 1};
        
        FNRUtils.reverse(test);
        
        assertTrue(Arrays.equals(expected, test));
    }
    
    @Test
    public void testPBKDF2() throws GeneralSecurityException {
        assertTrue(FNRUtils.createAes128KeyWithPBKDF2("pass", "salt").length > 0);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testPBKDF2NullPassphraseStrGuard() throws GeneralSecurityException {
        FNRUtils.createAes128KeyWithPBKDF2(null, "test");
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testPBKDF2NullSaltStrGuard() throws GeneralSecurityException {
        FNRUtils.createAes128KeyWithPBKDF2("test", null);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testPBKDF2EmptyPassphraseStrGuard() throws GeneralSecurityException {
        FNRUtils.createAes128KeyWithPBKDF2("", "test");
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testPBKDF2EmptySaltStrGuard() throws GeneralSecurityException {
        FNRUtils.createAes128KeyWithPBKDF2("test", "");
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testPBKDF2NullPassphraseGuard() throws GeneralSecurityException {
        FNRUtils.createAes128KeyWithPBKDF2(null, new byte[1]);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testPBKDF2NullSaltGuard() throws GeneralSecurityException {
        FNRUtils.createAes128KeyWithPBKDF2(new byte[1], null);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testPBKDF2EmptyPassphraseGuard() throws GeneralSecurityException {
        FNRUtils.createAes128KeyWithPBKDF2(new byte[0], new byte[1]);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testPBKDF2EmptySaltGuard() throws GeneralSecurityException {
        FNRUtils.createAes128KeyWithPBKDF2(new byte[1], new byte[0]);
    }
    
    @Test
    public void fixCoberturaCoverage() throws GeneralSecurityException, IllegalArgumentException, InstantiationException, IllegalAccessException, InvocationTargetException {
        Constructor<?> privateConstructor = FNRUtils.class.getDeclaredConstructors()[0];
        privateConstructor.setAccessible(true);
        privateConstructor.newInstance((Object[]) null);
    }
}
