# pusoba

# Custom cipher (ARM64 Go assembly & Go)
Block encryption algorithm with native optimizations on Go Assembly (ARM64). 

## Description 
Experimental symmetric cipher  which created for studying cryptographic properties and studying low-level optimizations 

- *Block size: 24*
- *Key length: 64 bit*
- *Key count: 2 (2 * 64bit-keys)*
- *Optimisation: math rounds implemented on Go assembly (ARM64)*
- *Avalanche/KeyBitFlip: %50.88*
- *Avalanche/AdjacentCounter: %51.51*
- *Avalanche/MixerFunction: %50.22*

## Repository structure

- `go_version/`: generic // filename **crypto.go**
- `asm_version/`: only ARM64  // folder name **asm**

## Start for Go assembly (ARM64)
```bash
cd asm 
go run .
```
## Start for generic (any)
```bash
go run crypto.go
 ```
## Especially 
- `low-level realization for symmetry PRNG-based stream cipher on the Go assembly`
**Optimisation ARM64:**
- `Loop unrolling procesed with 24-byte(3x-uint64) for one iteration`
- `Using R0-R30 register and byte rotate(*LSR*/*ROR*)`
- `Golden ratio constant(*0x9e3779b97f4a7c15*) uses to protect from linear and differential attacks`
