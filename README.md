FNR Cipher
=========
FNR Cipher is a Java implementation for [Flexible Naor and Reingold](http://eprint.iacr.org/2014/421) encryption scheme.

[![Build Status](https://travis-ci.org/octabase/fnr-java.svg?branch=master)](https://travis-ci.org/octabase/fnr-java) [![Coverage Status](https://coveralls.io/repos/octabase/fnr-java/badge.svg?branch=master&service=github)](https://coveralls.io/github/octabase/fnr-java?branch=master)

---

It's simple. If you give an integer, you get a different integer. This is two-way operation. That means, if you give the different integer and you get the original integer. The FNR algorithm preserves your data size, no expand or shrink.

The FNR algorithm is useful for small data types up to 128 bits data. FNR Cipher Java library provides some built-in codecs for basic data types encrpytion.

----

#### Built-In Supported Java Types:
| Java Type    | Codec              | Notes  |
| :----------- | :-------------------|:-------------------------------------------------- |
| Byte         | FNRCodec.BYTE       | NP_SIGN codec not preserve sign.                   |
| Short        | FNRCodec.SHORT      | NP_SIGN codec not preserve sign.                   |
| Character    | FNRCodec.CHAR       | NP_SIGN codec not preserve sign.                   |
| Integer      | FNRCodec.INT        | NP_SIGN codec not preserve sign.                   |
| Float        | FNRCodec.FLOAT      | NP_SIGN codec not preserve sign.                   |
| Long         | FNRCodec.LONG       | NP_SIGN_EXP codec not preserve sign and exponent.  |
| Double       | FNRCodec.DOUBLE     | NP_SIGN_EXP codec not preserve sign and exponent.  |
| BigInteger   | FNRCodec.BIGINT_128 | The acceptable value range is -2^127 to 2^127-1 or 0 to 2^128-1 |
| Date         | FNRCodec.DATE       | -      |
| Inet4Address | FNRCodec.IPV4       | -      |
| Inet6Address | FNRCodec.IPV6       |      |
> **Note:** All numeric codecs works as little-endian for compatibility to another platforms and preserves sign and exponents as default.



#### Install [![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.octa.security/fnr/badge.svg)](https://maven-badges.herokuapp.com/maven-central/io.octa.security/fnr)
```xml
<dependency>
	<groupId>io.octa.security</groupId>
	<artifactId>fnr</artifactId>
	<version>1.0.0</version>
</dependency>
```
#### Usage
```java
String passphrase = "this is a password";
String salt = "this is a salt value"; // for built-in PBKDF2 key generation.

// Integer encryption
int numBits = FNRCodec.INT.getRequiredKeyNumBits();
FNRKey key = FNRCipher.createKeyWithPBKDF2(passphrase, salt, numBits);
FNRTweak tweak = key.generateTweak("this is a tweak value");
        
int raw = 42;

int encrypted = FNRCipher.encrypt(FNRCodec.INT, key, tweak, raw);
int decrypted = FNRCipher.decrypt(FNRCodec.INT, key, tweak, encrypted);

System.out.println("raw: " + raw);             // prints 42
System.out.println("encrypted: " + encrypted); // prints 1432569698
System.out.println("decrypted: " + decrypted); // prints 42

// IP encryption
numBits = FNRCodec.IPV4.getRequiredKeyNumBits();
key = FNRCipher.createKeyWithPBKDF2(passphrase, salt, numBits);
tweak = key.generateTweak("this is a tweak value");

Inet4Address rawIP = (Inet4Address) Inet4Address.getByName("8.4.4.2");

Inet4Address encryptedIP = FNRCipher.encrypt(FNRCodec.IPV4, key, tweak, rawIP);
Inet4Address decryptedIP = FNRCipher.decrypt(FNRCodec.IPV4, key, tweak, encryptedIP);

System.out.println("raw: " + rawIP);             // prints 8.4.4.2
System.out.println("encrypted: " + encryptedIP); // prints 25.123.159.248
System.out.println("decrypted: " + decryptedIP); // prints 8.4.4.2
```

#### Performance
| Library/Method | AES Encryption Method | Encryption       | Decryption       | Notes  |
| :------------- | :-------------------- | ---------------: | ---------------: | :----- |
| [Reference C implementaion](https://github.com/cisco/libfnr) | OpenSSL               | 573560.582 ops/s | 570522.579 ops/s | OpenSSL uses [CPU AES Extension](https://en.wikipedia.org/wiki/AES_instruction_set)  |
| FNR Java       | Built-In              | 198160.740 ops/s | 202775.251 ops/s | AES encryption with built-in minimal, optimized cipher |
| [Java binding for Reference C implementaion](https://github.com/cisco/jfnr) | OpenSSL               | 105766.458 ops/s | 106495.132 ops/s | I think JNI round-trip overhead is cause of bottleneck. |
| FNR Java       | JCE                   |   8998.094 ops/s |  81175.897 ops/s | AES encryption with standard Java Cryptography Extension |
> **Note:** Tested on Intel(R) Core(TM) i7-4700MQ CPU @ 2.40GHz.

FNR is designed by Sashank Dara (sadara@cisco.com), Scott Fluhrer (sfluhrer@cisco.com). ([Reference C implementaion](https://github.com/cisco/libfnr))

Java implementation was written by Mehmet Gurevin (mehmet.gurevin@octabase.com)

Copyright (c) 2015-2016, Octabase, Inc. All Rights Reserved.
