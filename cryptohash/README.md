# crypto

A Kotlin Multiplatform Mobile library to provide a set of cryptographic (and
not so cryptographic) hashing functions.

The following hashing algorithms are supported

- Adler32
- BLAKE-224, BLAKE-256, BLAKE-384, BLAKE-512
- Blake2b-160, Blake2b-256, Blake2b-384, Blake2b-512, Blake2s-128, Blake2s-160,
  Blake2s-224, Blake2s-256
- Blake3
- BMW-224, BMW-256, BMW-384, BMW-512
- CRC32
- cSHAKE
- CubeHash-224, CubeHash-256, CubeHash-384, CubeHash-512
- DSTU7564-256, DSTU7564-384, DSTU7564-512
- ECHO-224, ECHO-256, ECHO-384, ECHO-512
- Fugue-224, Fugue-256, Fugue-384, Fugue-512
- GOST3411-94, GOST3411-2012-256, GOST3411-2012-512
- Groestl-224, Groestl-256, Groestl-384, Groestl-512
- Hamsi-224, Hamsi-256, Hamsi-384, Hamsi-512
- Haraka-256, Haraka-512
- HAVAL-128-3, HAVAL-128-4, HAVAL-128-5, HAVAL-160-3, HAVAL-160-4, HAVAL-160-5,
  HAVAL-192-3, HAVAL-192-4, HAVAL-192-5, HAVAL-224-3, HAVAL-224-4, HAVAL-224-5,
  HAVAL-256-3, HAVAL-256-4, HAVAL-256-5
- JH-224, JH-256, JH-384, JH-512
- Keccak-224, Keccak-256, Keccak-288, Keccak-384, Keccak-512
- Luffa-224, Luffa-256, Luffa-384, Luffa-512
- MD2, MD4, MD5
- PANAMA
- RadioGatun32, RadioGatun64
- RIPEMD, RIPEMD-128, RIPEMD-160, RIPEMD-256, RIPEMD-320
- SHA-0, SHA-1, SHA-224, SHA-384, SHA-512, SHA-512/224, SHA-512/256
- SHA3-224, SHA3-256, SHA3-384, SHA3-512
- Shabal-192, Shabal-224, Shabal-256, Shabal-384, Shabal-512
- SHAKE128, SHAKE256
- SHAvite-224, SHAvite-256, SHAvite-384, SHAvite-512
- SIMD-224, SIMD-256, SIMD-384, SIMD-512
- Skein-256-128, Skein-256-160, Skein-256-224, Skein-256-256, Skein-512-128,
  Skein-512-160, Skein-512-224, Skein-512-256, Skein-512-384, Skein-512-512,
  Skein-1024-384, Skein-1024-512, Skein-1024-1024
- SM3
- Tiger, Tiger2
- Whirlpool, Whirlpool-0, Whirlpool-T

Inspired by the Flutter [crypto](https://pub.dev/packages/crypto)
package. Pure Kotlin implementations based on [saphir](https://github.com/sfuhrm/saphir-hash),
[Bouncy Castle](https://github.com/bcgit/bc-java/) and [blake3](https://github.com/rctcwyvrn/blake3).
