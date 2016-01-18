package io.octa.security.fnr;

import java.io.IOException;
import java.security.GeneralSecurityException;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import com.cisco.fnr.FNR;

import io.octa.security.fnr.FNRCipher;
import io.octa.security.fnr.FNRKey;
import io.octa.security.fnr.FNRTweak;
import io.octa.security.fnr.FNRUtils;

@Warmup(iterations = 5)
@Fork(2)
@Measurement(iterations = 5)
@State(Scope.Thread)
public class FNRCipherBenchmarkTest {
    private FNRKey key;
    private FNRKey keyBuiltIn;

    private FNRTweak tweak;

    private String passphrase = "this is a password";
    private String salt = "this is a salt value";
    private String tweakVal = "zero";

    private byte raw[] = new byte[] {
            (byte) 0x56, (byte) 0x9c, (byte) 0x3c, (byte) 0x57,
            (byte) 0xb3, (byte) 0x09, (byte) 0xdb, (byte) 0xba,
            (byte) 0x59, (byte) 0x65, (byte) 0x35, (byte) 0xff,
            (byte) 0xb5, (byte) 0x7c, (byte) 0x5a, (byte) 0x24};

    private byte enc[];

    private FNR jnaCipher;

    @Setup
    public void init() throws GeneralSecurityException {
        byte[] aes128Key = FNRUtils.createAes128KeyWithPBKDF2(passphrase, salt);

        key = new FNRKey(aes128Key, 128, false);
        keyBuiltIn = new FNRKey(aes128Key, 128, true);

        tweak = key.generateTweak(tweakVal);

        jnaCipher = new FNR(aes128Key, tweakVal, 128);

        enc = jnaCipher.encrypt(raw);
    }

    @Benchmark
    public void FNRJavaJNAEncryption() throws GeneralSecurityException {
        FNRCipher.encrypt(key, tweak, raw);
    }
    
    @Benchmark
    public void FNRJavaBuilInAesEncryption() throws GeneralSecurityException {
        FNRCipher.encrypt(keyBuiltIn, tweak, raw);
    }
    
    @Benchmark
    public void FNRJavaJNADecryption() throws GeneralSecurityException {
        FNRCipher.encrypt(key, tweak, enc);
    }
    
    @Benchmark
    public void FNRJavaBuiltInAesDecryption() throws GeneralSecurityException {
        FNRCipher.encrypt(keyBuiltIn, tweak, enc);
    }

    @Benchmark
    public void JNAEncryption() throws GeneralSecurityException {
        jnaCipher.encrypt(raw);
    }

    @Benchmark
    public void JNADecryption() throws GeneralSecurityException {
        jnaCipher.decrypt(enc);
    }

    public static void main(String... args) throws RunnerException, IOException {
        Options opt = new OptionsBuilder()
                .include(".*" + FNRCipherBenchmarkTest.class.getSimpleName() + ".*")
                .build();
        new Runner(opt).run();
    }
}
