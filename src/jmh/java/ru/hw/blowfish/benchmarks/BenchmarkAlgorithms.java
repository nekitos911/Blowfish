//package ru.hw.blowfish.benchmarks;
//
//import org.openjdk.jmh.annotations.*;
//import org.openjdk.jmh.infra.Blackhole;
//import org.openjdk.jmh.runner.Runner;
//import org.openjdk.jmh.runner.options.Options;
//import org.openjdk.jmh.runner.options.OptionsBuilder;
//import ru.hw.blowfish.Blowfish;
//
//import java.util.concurrent.TimeUnit;
//
//@BenchmarkMode(Mode.AverageTime)
//@OutputTimeUnit(TimeUnit.MILLISECONDS)
//@State(Scope.Benchmark)
//public class BenchmarkAlgorithms {
//    private Blowfish blowfish;
//
//    @Setup
//    public void setup() {
//        blowfish = new Blowfish("testKey1");
//    }
//
//    @Benchmark
//    @Fork(value = 1, warmups = 1)
//    @Warmup(iterations = 1)
//    public String benchmarkEncipher() {
//        return blowfish.encipher("test".repeat(100 * 100));
//    }
//}
