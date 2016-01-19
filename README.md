FNR Cipher
=========
FNR Cipher is a Java implementation for [Flexible Naor and Reingold](http://eprint.iacr.org/2014/421) encryption scheme.

[![Build Status](https://travis-ci.org/octabase/fnr-java.svg?branch=master)](https://travis-ci.org/octabase/fnr-java) [![Coverage Status](https://coveralls.io/repos/octabase/fnr-java/badge.svg?branch=master&service=github)](https://coveralls.io/github/octabase/fnr-java?branch=master)

---

It's simple. If you give an integer, you get a encrypted integer. This is two-way operation. That means, if you give the encrypted integer also you get the original integer. The FNR algorithm preserves your data size, no expand, no shrink. All operation space limited by key bit length.

This method also known as [format preserving encryption](https://en.wikipedia.org/wiki/Format-preserving_encryption). FNR algorithm is useful for small data types (up to 128 bits) such as credit card or user ids.

FNR uses AES-128 internally in each encryption/decryption rounds. FNR Java contains optimized and minimal AES-128 pure Java cipher. It may be a good choise instead of Java Cryptography Extension. This library don't have any dependencies, it fits for Andorid.

The FNR Java library is binary compatible with reference C implementation.

FNR Java provides some built-in codecs for basic data types encryption.

----

#### Built-In Supported Java Types:
| Java Type    | Codec              | Notes  |
| :----------- | :-------------------|:-------------------------------------------------- |
| Byte         | FNRCodec.BYTE       | NP_SIGN codec not preserve sign.                   |
| Short        | FNRCodec.SHORT      | NP_SIGN codec not preserve sign.                   |
| Character    | FNRCodec.CHAR       | NP_SIGN codec not preserve sign.                   |
| Integer      | FNRCodec.INT        | NP_SIGN codec not preserve sign.                   |
| Float        | FNRCodec.FLOAT      | NP_SIGN_EXP codec not preserve sign and exponent.  |
| Long         | FNRCodec.LONG       | NP_SIGN codec not preserve sign.                   |
| Double       | FNRCodec.DOUBLE     | NP_SIGN_EXP codec not preserve sign and exponent.  |
| BigInteger   | FNRCodec.BIGINT_128 | The acceptable value range are -2^127 to 2^127-1 or 0 to 2^128-1 |
| Date         | FNRCodec.DATE       | -      |
| Inet4Address | FNRCodec.IPV4       | -      |
| Inet6Address | FNRCodec.IPV6       |        |
> **Note:** All numeric codecs run as litte-endian for compatibiliy with other platform like C or Go and preserve sign and exponents as default.

#### Install [![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.octa.security/fnr/badge.svg)](https://maven-badges.herokuapp.com/maven-central/io.octa.security/fnr)
```xml
<dependency>
	<groupId>io.octa.security</groupId>
	<artifactId>fnr</artifactId>
	<version>1.0.1</version>
</dependency>
```

#### Usage
```java
String passphrase = "this is a password";
String salt = "this is a salt value"; // for built-in PBKDF2 key generation.

byte[] aesKey = FNRUtils.createAes128KeyWithPBKDF2(passphrase, salt);

// Integer encryption
FNRKey key = new FNRKey(aesKey, FNRCodec.INT.getRequiredKeyNumBits());
FNRTweak tweak = key.generateTweak("this is a tweak value");
        
int raw = 42;

int encrypted = FNRCipher.encrypt(FNRCodec.INT, key, tweak, raw);
int decrypted = FNRCipher.decrypt(FNRCodec.INT, key, tweak, encrypted);

System.out.println("raw: " + raw);             // prints 42
System.out.println("encrypted: " + encrypted); // prints 1432569698
System.out.println("decrypted: " + decrypted); // prints 42

// IP encryption
key = new FNRKey(aesKey, FNRCodec.IPV4.getRequiredKeyNumBits());
tweak = key.generateTweak("this is a tweak value");

Inet4Address rawIP = (Inet4Address) Inet4Address.getByName("8.4.4.2");

Inet4Address encryptedIP = FNRCipher.encrypt(FNRCodec.IPV4, key, tweak, rawIP);
Inet4Address decryptedIP = FNRCipher.decrypt(FNRCodec.IPV4, key, tweak, encryptedIP);

System.out.println("raw: " + rawIP);             // prints 8.4.4.2
System.out.println("encrypted: " + encryptedIP); // prints 25.123.159.248
System.out.println("decrypted: " + decryptedIP); // prints 8.4.4.2
```

#### Performance
| Library        | AES Encryption Method | Encryption       | Decryption       | Notes  |
| :------------- | :-------------------- | ---------------: | ---------------: | :----- |
| [Reference C implementaion](https://github.com/cisco/libfnr) | OpenSSL               | 229141.720 ops/s | 230386.135 ops/s | OpenSSL uses [CPU AES Extension](https://en.wikipedia.org/wiki/AES_instruction_set)  |
| FNR Java       | Built-In              | 198160.740 ops/s | 202775.251 ops/s | AES encryption with built-in minimal, optimized cipher |
| [Java binding for Reference C implementaion](https://github.com/cisco/jfnr) | OpenSSL               | 105766.458 ops/s | 106495.132 ops/s | I think the cause of bottleneck is JNI round-trip overhead. |
| FNR Java       | JCE                   |  82998.094 ops/s |  81175.897 ops/s | AES encryption with standard Java Cryptography Extension |

> Tested on Intel(R) Core(TM) i7-4700MQ CPU @ 2.40GHz.
>
> Java Benchmark: [FNRCipherBenchmarkTest.java](https://github.com/octabase/fnr-java/blob/master/src/test/java/io/octa/security/fnr/FNRCipherBenchmarkTest.java)
> ```
> JMH 1.11.3 (released 3 days ago)
> VM version: JDK 1.8.0_66, VM 25.66-b17
> VM invoker: /usr/lib/jvm/java-8-oracle/jre/bin/java
> VM options: <none>
> Warmup: 5 iterations, 1 s each
> Measurement: 5 iterations, 1 s each
> Timeout: 10 min per iteration
> Threads: 1 thread, will synchronize iterations
> Benchmark mode: Throughput, ops/time
> ```
>
> C Benchmark: [bench.c](https://github.com/cisco/libfnr/blob/master/test/bench.c)
> ```
> GCC compiles with -O2 and use OpenSSL 1.0.2d
> ```
 


FNR is designed by Sashank Dara (sadara@cisco.com), Scott Fluhrer (sfluhrer@cisco.com). ([Reference C implementaion](https://github.com/cisco/libfnr))

Java implementation was written by Mehmet Gurevin (mehmet.gurevin@octabase.com)

Copyright (c) 2015-2016, Octabase, Inc. All Rights Reserved.
