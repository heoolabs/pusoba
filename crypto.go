package main



import (

	"crypto/rand"

	"encoding/binary"

	"fmt"

	"math/bits"

	"runtime"

	"time"

)



const MIX_CONST = 0x9e3779b97f4a7c15



func mixer(keyReg, ctrReg uint64) uint64 {

	r5 := keyReg + ctrReg

	r5 ^= MIX_CONST

	r5 *= MIX_CONST

	r7 := r5

	r5 = bits.RotateLeft64(r5, -32)

	r7 = bits.RotateLeft64(r7, -38)

	r5 *= 7

	r7 *= 3

	r5 ^= r7

	r5 *= MIX_CONST

	r5 = bits.RotateLeft64(r5, -13)

	return r5

}

func mixer2(keyReg, ctrReg uint64) uint64 {

	r9 := mixer(keyReg, ctrReg)

	r7 := keyReg + 1

	r7 ^= MIX_CONST

	return mixer(r7, r9)

}

func CustomCrypt(packet []byte, keyLo, keyHi, counter uint64) {

	r13 := keyLo + keyHi

	r14 := keyLo ^ keyHi

	r19 := (keyLo * 3) + (keyHi * 7)

	r4 := counter

	for len(packet) >= 24 {

		r20 := mixer2(r13, r4)

		r21 := mixer2(r14, r4+1)

		r22 := mixer2(r19, r4+2)

		b0 := binary.LittleEndian.Uint64(packet[0:8]) ^ r20

		b1 := binary.LittleEndian.Uint64(packet[8:16]) ^ r21

		b2 := binary.LittleEndian.Uint64(packet[16:24]) ^ r22

		binary.LittleEndian.PutUint64(packet[0:8], b0)

		binary.LittleEndian.PutUint64(packet[8:16], b1)

		binary.LittleEndian.PutUint64(packet[16:24], b2)

		r4 += 3

		packet = packet[24:]

	}

	for len(packet) >= 8 {

		r5 := mixer2(r13, r4)

		b := binary.LittleEndian.Uint64(packet[0:8]) ^ r5

		binary.LittleEndian.PutUint64(packet[0:8], b)

		r4 += 1

		packet = packet[8:]

	}

	if len(packet) > 0 {

		r5 := mixer2(r13, r4)



		for i := 0; i < len(packet); i++ {

			packet[i] ^= byte(r5)

			r5 >>= 8

		}

	}

}



func runEmbeddedBenchmark(name string, size int, iterations int) {

	packet := make([]byte, size)

	_, _ = rand.Read(packet)



	keyLo := uint64(0x1122334455667788)

	keyHi := uint64(0x99AABBCCDDEEFF00)

	counter := uint64(1)

	runtime.GC()

	var memBefore runtime.MemStats

	runtime.ReadMemStats(&memBefore)

	startTime := time.Now()

	for i := 0; i < iterations; i++ {

		CustomCrypt(packet, keyLo, keyHi, counter)

		counter++

	}

	elapsed := time.Since(startTime)

	var memAfter runtime.MemStats

	runtime.ReadMemStats(&memAfter)

	totalBytes := int64(size) * int64(iterations)

	nsPerOp := elapsed.Nanoseconds() / int64(iterations)

	mbPerSecond := (float64(totalBytes) / (1024 * 1024)) / elapsed.Seconds()

	bytesAllocated := memAfter.TotalAlloc - memBefore.TotalAlloc

	allocsCount := memAfter.Mallocs - memBefore.Mallocs

	bytesPerOp := bytesAllocated / uint64(iterations)

	allocsPerOp := allocsCount / uint64(iterations)

	fmt.Printf("%-24s\t%8d\t%8d ns/op\t%8.2f MB/s\t%8d B/op\t%8d allocs/op\n",

		name, iterations, nsPerOp, mbPerSecond, bytesPerOp, allocsPerOp)

}



func main() {
 fmt.Println("That is generic version")

	fmt.Println("--- Embedded Benchmark (Simulated benchmem) ---")

	runEmbeddedBenchmark("BenchmarkCustomCrypt/1KB", 1024, 1_000_000)

	runEmbeddedBenchmark("BenchmarkCustomCrypt/64KB", 64*1024, 50_000)

	runEmbeddedBenchmark("BenchmarkCustomCrypt/1MB", 1024*1024, 3_500)

}
