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

import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.UnknownHostException;
import java.util.Date;

public interface FNRCodec<T> {
    public byte[] encode(T input);
    
    public T decode(byte[] input);
    
    public int getRequiredKeyNumBits();

    public static final FNRCodec<Boolean> BOOL = new FNRCodec<Boolean>() {
        @Override
        public byte[] encode(Boolean input) {
            return new byte[] {(byte) (input ? 0x01 : 0x00)};
        }

        @Override
        public Boolean decode(byte[] input) {
            return input[0] == 0x01 ? true : false;
        }

        @Override
        public int getRequiredKeyNumBits() {
            return 1;
        }
    };

    public static final FNRCodec<Byte> BYTE = new FNRCodec<Byte>() {
        @Override
        public byte[] encode(Byte input) {
            return new byte[] {input};
        }

        @Override
        public Byte decode(byte[] input) {
            return input[0];
        }

        @Override
        public int getRequiredKeyNumBits() {
            return Byte.SIZE - 1;
        }
    };

    public static final FNRCodec<Byte> BYTE_NP_SIGN = new FNRCodec<Byte>() {
        @Override
        public byte[] encode(Byte input) {
            return BYTE.encode(input);
        }

        @Override
        public Byte decode(byte[] input) {
            return BYTE.decode(input);
        }

        @Override
        public int getRequiredKeyNumBits() {
            return Byte.SIZE;
        }
    };

    public static final FNRCodec<Short> SHORT = new FNRCodec<Short>() {
        @Override
        public byte[] encode(Short input) {
            byte[] data = new byte[Short.SIZE / Byte.SIZE];

            data[1] = (byte) (input >> 8);
            data[0] = (byte) (int) input;

            return data;
        }

        @Override
        public Short decode(byte[] input) {
            return (short) (((input[1] & 0xFF) <<  8) | ( input[0] & 0xFF));
        }

        @Override
        public int getRequiredKeyNumBits() {
            return Short.SIZE - 1;
        }
    };

    public static final FNRCodec<Short> SHORT_NP_SIGN = new FNRCodec<Short>() {
        @Override
        public byte[] encode(Short input) {
            return SHORT.encode(input);
        }

        @Override
        public Short decode(byte[] input) {
            return SHORT.decode(input);
        }

        @Override
        public int getRequiredKeyNumBits() {
            return Short.SIZE;
        }
    };

    public static final FNRCodec<Character> CHAR = new FNRCodec<Character>() {
        @Override
        public byte[] encode(Character input) {
            return SHORT.encode((short) input.charValue());
        }

        @Override
        public Character decode(byte[] input) {
            return Character.valueOf((char) (short) SHORT.decode(input));
        }

        @Override
        public int getRequiredKeyNumBits() {
            return SHORT.getRequiredKeyNumBits();
        }
    };

    public static final FNRCodec<Character> CHAR_NP_SIGN = new FNRCodec<Character>() {
        @Override
        public byte[] encode(Character input) {
            return CHAR.encode(input);
        }

        @Override
        public Character decode(byte[] input) {
            return CHAR.decode(input);
        }

        @Override
        public int getRequiredKeyNumBits() {
            return Character.SIZE;
        }
    };

    public static final FNRCodec<Integer> INT = new FNRCodec<Integer>() {
        @Override
        public byte[] encode(Integer input) {
            byte[] data = new byte[Integer.SIZE / Byte.SIZE];

            data[3] = (byte) (input >> 24);
            data[2] = (byte) (input >> 16);
            data[1] = (byte) (input >> 8);
            data[0] = (byte) (int) input;

            return data;
        }

        @Override
        public Integer decode(byte[] input) {
            return ((input[3])        << 24)
                 | ((input[2] & 0xFF) << 16)
                 | ((input[1] & 0xFF) <<  8)
                 | ( input[0] & 0xFF);
        }

        @Override
        public int getRequiredKeyNumBits() {
            return Integer.SIZE - 1;
        }
    };

    public static final FNRCodec<Integer> INT_NP_SIGN = new FNRCodec<Integer>() {
        @Override
        public byte[] encode(Integer input) {
            return INT.encode(input);
        }

        @Override
        public Integer decode(byte[] input) {
            return INT.decode(input);
        }

        @Override
        public int getRequiredKeyNumBits() {
            return Integer.SIZE;
        }
    };

    public static final FNRCodec<Float> FLOAT = new FNRCodec<Float>() {
        @Override
        public byte[] encode(Float input) {
            return INT.encode(Float.floatToRawIntBits(input));
        }

        @Override
        public Float decode(byte[] input) {
            return Float.intBitsToFloat(INT.decode(input));
        }

        @Override
        public int getRequiredKeyNumBits() {
            return 23;
        }
    };

    public static final FNRCodec<Float> FLOAT_NP_SIGN_EXP = new FNRCodec<Float>() {
        @Override
        public byte[] encode(Float input) {
            return FLOAT.encode(input);
        }

        @Override
        public Float decode(byte[] input) {
            return FLOAT.decode(input);
        }

        @Override
        public int getRequiredKeyNumBits() {
            return Float.SIZE;
        }
    };

    public static final FNRCodec<Long> LONG = new FNRCodec<Long>() {
        @Override
        public byte[] encode(Long input) {
            byte[] data = new byte[Long.SIZE / Byte.SIZE];
            
            data[7] = (byte) (input >> 56);
            data[6] = (byte) (input >> 48);
            data[5] = (byte) (input >> 40);
            data[4] = (byte) (input >> 32);
            data[3] = (byte) (input >> 24);
            data[2] = (byte) (input >> 16);
            data[1] = (byte) (input >> 8);
            data[0] = (byte) (long) input;

            return data;
        }

        @Override
        public Long decode(byte[] input) {
            return  ((((long) input[7])        << 56)
                   | (((long) input[6] & 0xFF) << 48)
                   | (((long) input[5] & 0xFF) << 40)
                   | (((long) input[4] & 0xFF) << 32)
                   | (((long) input[3] & 0xFF) << 24)
                   | (((long) input[2] & 0xFF) << 16)
                   | (((long) input[1] & 0xFF) <<  8)
                   | ( (long) input[0] & 0xFF));
        }

        @Override
        public int getRequiredKeyNumBits() {
            return Long.SIZE - 1;
        }
    };

    public static final FNRCodec<Long> LONG_NP_SIGN = new FNRCodec<Long>() {
        @Override
        public byte[] encode(Long input) {
            return LONG.encode(input);
        }

        @Override
        public Long decode(byte[] input) {
            return LONG.decode(input);
        }

        @Override
        public int getRequiredKeyNumBits() {
            return Long.SIZE;
        }
    };

    public static final FNRCodec<Double> DOUBLE = new FNRCodec<Double>() {
        @Override
        public byte[] encode(Double input) {
            return LONG.encode(Double.doubleToRawLongBits(input));
        }

        @Override
        public Double decode(byte[] input) {
            return Double.longBitsToDouble(LONG.decode(input));
        }

        @Override
        public int getRequiredKeyNumBits() {
            return 52;
        }
    };

    public static final FNRCodec<Double> DOUBLE_NP_SIGN_EXP = new FNRCodec<Double>() {
        @Override
        public byte[] encode(Double input) {
            return DOUBLE.encode(input);
        }

        @Override
        public Double decode(byte[] input) {
            return DOUBLE.decode(input);
        }

        @Override
        public int getRequiredKeyNumBits() {
            return Double.SIZE;
        }
    };

    public static final FNRCodec<Inet4Address> IPV4 = new FNRCodec<Inet4Address>() {
        @Override
        public byte[] encode(Inet4Address input) {
            byte address[] = input.getAddress();
            
            FNRUtils.reverse(address);
            
            return address;
        }

        @Override
        public Inet4Address decode(byte[] input) {
            try {
                FNRUtils.reverse(input);
                
                return (Inet4Address) Inet4Address.getByAddress(input);
            } catch (UnknownHostException e) {
                throw new IllegalArgumentException(e);
            }
        }

        @Override
        public int getRequiredKeyNumBits() {
            return Integer.SIZE;
        }
    };

    public static final FNRCodec<Inet6Address> IPV6 = new FNRCodec<Inet6Address>() {
        @Override
        public byte[] encode(Inet6Address input) {
            byte address[] = input.getAddress();
            
            FNRUtils.reverse(address);
            
            return address;
        }

        @Override
        public Inet6Address decode(byte[] input) {
            try {
                FNRUtils.reverse(input);

                return (Inet6Address) Inet6Address.getByAddress(input);
            } catch (UnknownHostException e) {
                throw new IllegalArgumentException(e);
            }
        }

        @Override
        public int getRequiredKeyNumBits() {
            return 128;
        }
    };

    public static final FNRCodec<Date> DATE = new FNRCodec<Date>() {
        @Override
        public byte[] encode(Date input) {
            return LONG.encode(input.getTime());
        }

        @Override
        public Date decode(byte[] input) {
            return new Date(LONG.decode(input));
        }

        @Override
        public int getRequiredKeyNumBits() {
            return 64;
        }
    };

    public static final FNRCodec<BigInteger> BIGINT_128 = new FNRCodec<BigInteger>() {
        @Override
        public byte[] encode(BigInteger input) {
            byte[] data = input.toByteArray();

            if (data.length > 16) {
                throw new IllegalArgumentException();
            } else if (data.length < 16) {
                byte[] wrapped = new byte[16];

                System.arraycopy(data, 0, wrapped, 16 - data.length, data.length);

                if (input.signum() == -1) {
                    for (int i = 0; i < 16 - data.length; i++) {
                        wrapped[i] |= 0xFF;
                    }
                }

                data = wrapped;
            }

            FNRUtils.reverse(data);

            return data;
        }

        @Override
        public BigInteger decode(byte[] input) {
            if (input.length != 16) {
                throw new IllegalArgumentException();
            }

            FNRUtils.reverse(input);
            
            return new BigInteger(input);
        }

        @Override
        public int getRequiredKeyNumBits() {
            return 127;
        }
    };

    public static final FNRCodec<BigInteger> BIGINT_128_NP_SIGN = new FNRCodec<BigInteger>() {
        @Override
        public byte[] encode(BigInteger input) {
            return BIGINT_128.encode(input);
        }

        @Override
        public BigInteger decode(byte[] input) {
            if (input.length != 16) {
                throw new IllegalArgumentException();
            }

            return BIGINT_128.decode(input);
        }

        @Override
        public int getRequiredKeyNumBits() {
            return 128;
        }
    };
}
