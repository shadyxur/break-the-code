# CSCI 7954 Weak cipher Lab

**Student Name:** Dmitri Kharchevnikov  
**Course:** CSCI 7954 - Advanced Topics in Cybersecurity  
**Institution:** Augusta University  
**Date:** September 29, 2025

---

## 1. Introduction

This report describes the cryptanalysis of a simple 64-bit block cipher using 64-bit keys. The objective was to recover the encryption key given a single known plaintext-ciphertext pair. Through analysis of the cipher's design, I successfully identified critical vulnerabilities that allowed complete key recovery.

**Given Information:**
- Plaintext: `F5EF5D981B5DB510`
- Ciphertext: `2AAA8E541A37D5AF`
- Key: Unknown (to be determined)

---

## 2. Understanding the Cipher

The cipher operates on 64-bit blocks (8 bytes) with a 64-bit key through three sequential operations:

### Step 1: XOR with Key
The plaintext P is XORed with the key K to produce intermediate value D:
```
D = P ⊕ K
```
Where ⊕ represents bitwise XOR operation, computed as:
```
di = pi ⊕ ki, for i = 0 to 63
```

### Step 2: Rotation
The intermediate value D is rotated left by 17 bits to produce E:
```
E = D « 17
```

### Step 3: S-Box Substitution
Each byte of E is substituted using the AES S-Box to produce the final ciphertext C:
```
C0 = SBox[E0], C1 = SBox[E1], ..., C7 = SBox[E7]
```

---

## 3. Vulnerability Analysis

The cipher contains several critical vulnerabilities that make it insecure:

### 3.1 Invertibility
All three operations in SC-1 are completely reversible:
- **XOR is self-inverse**: If D = P ⊕ K, then K = P ⊕ D
- **Rotation is reversible**: A left rotation by 17 can be undone by a right rotation by 17
- **S-Box is bijective**: The AES S-Box has an inverse (InvSBox) that uniquely reverses each substitution

### 3.2 Single Round
The cipher performs only one round of operations. Modern secure ciphers like AES use multiple rounds (10-14 rounds) to provide security through confusion and diffusion.

### 3.3 Key Recovery from One Pair
With a single known plaintext-ciphertext pair, an attacker can work backwards through the cipher to recover the complete key. This is the fundamental flaw we exploit.

---

## 4. Attack Methodology

To recover the key, I reversed each operation in the opposite order:

### Step 1: Reverse S-Box Substitution
Apply the inverse S-Box to each byte of the ciphertext:
```
E = InvSBox[C]
E0 = InvSBox[C0], E1 = InvSBox[C1], ..., E7 = InvSBox[C7]
```

Result: `E = 9562E6FD43B2B51B`

### Step 2: Reverse Rotation
Reverse the 17-bit left rotation by performing a 17-bit right rotation:
```
D = E » 17
```

**Important Implementation Detail:** The PHP implementation stores bits in reverse order where array index 0 corresponds to bit 63 (MSB) rather than bit 0 (LSB). This means the rotation operation must account for this reversed indexing scheme. The PHP code performs:
```php
$t1 = array_slice($ctbits, 17);    // bits from index 17 to 63
$t2 = array_slice($ctbits, 0, 17); // bits from index 0 to 16
$ctbits = array_merge($t1, $t2);   // concatenate [17..63] + [0..16]
```

This array manipulation, combined with the reversed bit ordering, implements a rotate right operation in actual bit positions.

Result: `D = 5A8DCAB1737EA1D9`

### Step 3: Recover Key via XOR
Since D = P ⊕ K, we can recover K by XORing D with P:
```
K = P ⊕ D
```

Computing byte by byte:
```
K = F5EF5D981B5DB510 ⊕ 5A8DCAB1737EA1D9
K = AF629729682314C9
```

---

## 5. Implementation

The attack is implemented in Python to automate the key recovery process. The implementation includes command-line interface support, input validation, and verification logic.

### Core Algorithm
The main cipher-breaking function implements the three-step reversal process:

```python
def break_cipher(plaintext_hex, ciphertext_hex):
    """Break the SC-1 cipher and recover the key"""
    
    # Parse input
    P = hex_to_bytes(plaintext_hex)
    C = hex_to_bytes(ciphertext_hex)
    
    # Step 1: Reverse S-Box
    E = apply_inverse_sbox(C)
    
    # Step 2: Reverse Rotation
    E_bits = bytes_to_bits(E)
    D_bits = rotate_bits(E_bits, 17, direction='left')
    D = bits_to_bytes(D_bits)
    
    # Step 3: XOR to get key
    K = xor_bytes(P, D)
    
    return K
```

### Key Helper Functions

**Inverse S-Box Creation:**
```python
# Create inverse S-Box by inverting the lookup table
INV_SBOX = [0] * 256
for i in range(256):
    INV_SBOX[SBOX[i]] = i
```

**XOR Operation:**
```python
def xor_bytes(bytes1, bytes2):
    """XOR two byte arrays element-wise"""
    return [b1 ^ b2 for b1, b2 in zip(bytes1, bytes2)]
```

**Bit Rotation (accounting for PHP ordering):**
```python
def rotate_bits(bits, amount, direction='right'):
    """Rotate bit array accounting for reversed PHP bit storage"""
    if direction == 'right':
        # For decryption: slice and concatenate
        return bits[amount:] + bits[:amount]
    else:
        # For encryption: reverse direction
        split_point = 64 - amount
        return bits[split_point:] + bits[:split_point]
```

### Execution
The program can be run in multiple ways.

**Windows PowerShell:**
```powershell
# Use built-in sample data
python codeBreak.py

# Provide custom plaintext and ciphertext
python codeBreak.py -p F5EF5D981B5DB510 -c 2AAA8E541A37D5AF

# Quiet mode (output key only)
python codeBreak.py -p F5EF5D981B5DB510 -c 2AAA8E541A37D5AF -q
```
**Linux/macOS (bash):**
```bash
# Use built-in sample data
python3 codeBreak.py

# Provide custom plaintext and ciphertext
python3 codeBreak.py -p F5EF5D981B5DB510 -c 2AAA8E541A37D5AF

# Quiet mode (output key only)
python3 codeBreak.py -p F5EF5D981B5DB510 -c 2AAA8E541A37D5AF -q
```

When executed with the given plaintext-ciphertext pair, the program successfully recovers the key in under 0.01 seconds.

---

### Quick Access

Clone and run:

**Linux/macOS:**
```bash
git clone https://github.com/shadyxur/break-the-code.git
cd break-the-code
python3 codeBreak.py
```

**Windows PowerShell:**
```powershell
git clone https://github.com/shadyxur/break-the-code.git
cd break-the-code
python codeBreak.py
```


---

**End of Report**
