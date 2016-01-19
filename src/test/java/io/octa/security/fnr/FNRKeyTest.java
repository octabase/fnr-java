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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.BlockJUnit4ClassRunner;

@RunWith(BlockJUnit4ClassRunner.class)
public class FNRKeyTest extends FNRTestCase {
    @Test(expected = NullPointerException.class)
    public void testNullAesKeyGuard() throws GeneralSecurityException {
        new FNRKey(null, 2);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testWrongAesLengthKeyGuard() throws GeneralSecurityException {
        new FNRKey(new byte[15], 2);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testSmallNumBitsGuard() throws GeneralSecurityException {
        new FNRKey(randomAesKey(), 0);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testBigNumBitsGuard() throws GeneralSecurityException {
        new FNRKey(randomAesKey(), 129);
    }
    
    @Test(expected = NullPointerException.class)
    public void testNullTweakGuard() throws GeneralSecurityException {
        new FNRKey(randomAesKey(), 128).generateTweak((String) null);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testEmptyTweakGuard() throws GeneralSecurityException {
        new FNRKey(randomAesKey(), 128).generateTweak("");
    }
}
