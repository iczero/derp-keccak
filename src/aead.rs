/*
TODO: DerpCryptV1 (Ketje but worse)
1. pad10*1(key, 0b100) -> state, keccakf
2. pad10*1(nonce, 0b101) -> state, keccakf
3. state -> pad1, keccakf
4. state -> pad2, keccakf
5. additional data block 1 -> state, keccakf
6. pad10*1(additional data block 2, 0b110) -> state, keccakf
7. pad1 -> state, keccakf
8. state -> encrypt block 1, keccakf
9. plaintext block 1 -> state, keccakf
10. state -> encrypt block 2, keccakf
11. pad10*1(plaintext block 2, 0b111) -> state, keccakf
12. pad2 -> state, keccakf
13. state -> tag, keccakf
14. repeat 3-13 for more data with same key
*/