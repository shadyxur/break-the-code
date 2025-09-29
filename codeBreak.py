"""
SC-1 Cipher Breaker
This program breaks the SC-1 cipher by reversing its operations
to recover the encryption key from a known plaintext-ciphertext pair.

Usage:
    - Run without arguments to execute the built-in sample and optionally try interactive input.
    - Provide values on the command line:
            python codeBreak.py --plaintext F5EF5D981B5DB510 --ciphertext 2AAA8E541A37D5AF
        or short form:
            python codeBreak.py -p <plaintext> -c <ciphertext>
    - Use --quiet or -q to print only the recovered key (suitable for scripting).

Input should be 16 hex digits (spaces allowed), representing 8 bytes.
"""

# AES S-Box 
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Create Inverse S-Box
INV_SBOX = [0] * 256
for i in range(256):
    INV_SBOX[SBOX[i]] = i


def hex_to_bytes(hex_string):
    """Convert hex string to list of bytes"""
    hex_string = hex_string.replace(" ", "")  # Remove spaces
    return [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]


def bytes_to_hex(byte_list):
    """Convert list of bytes to hex string"""
    return ''.join([f'{b:02X}' for b in byte_list])


def bytes_to_bits(byte_list):
    """Convert bytes to bit array (PHP-style: index 0 = bit 63)"""
    bits = []
    for byte in byte_list:
        for i in range(7, -1, -1):  # MSB to LSB
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bit_list):
    """Convert bit array back to bytes"""
    bytes_result = []
    for i in range(0, len(bit_list), 8):
        byte = 0
        for j in range(8):
            if bit_list[i + j]:
                byte += (1 << (7 - j))
        bytes_result.append(byte)
    return bytes_result


def rotate_bits(bits, amount, direction='right'):
    """Rotate bit array (accounting for PHP's reversed ordering)"""
    if direction == 'right':
        # For decryption: rotate right in array space
        return bits[amount:] + bits[:amount]
    else:
        # For encryption: rotate left in array space
        split_point = 64 - amount
        return bits[split_point:] + bits[:split_point]


def apply_inverse_sbox(byte_list):
    """Apply inverse S-Box to each byte"""
    return [INV_SBOX[b] for b in byte_list]


def apply_sbox(byte_list):
    """Apply S-Box to each byte"""
    return [SBOX[b] for b in byte_list]


def xor_bytes(bytes1, bytes2):
    """XOR two byte arrays"""
    return [b1 ^ b2 for b1, b2 in zip(bytes1, bytes2)]


def break_cipher(plaintext_hex, ciphertext_hex):
    """
    Break the SC-1 cipher and recover the key
    
    Args:
        plaintext_hex: Plaintext as hex string (e.g., "F5EF5D981B5DB510")
        ciphertext_hex: Ciphertext as hex string (e.g., "2AAA8E541A37D5AF")
    
    Returns:
        Dictionary containing the key and intermediate steps
    """
    print("=" * 60)
    print("SC-1 CIPHER BREAKER")
    print("=" * 60)
    
    # Parse input
    P = hex_to_bytes(plaintext_hex)
    C = hex_to_bytes(ciphertext_hex)
    
    print(f"\n📝 Input:")
    print(f"   Plaintext:  {bytes_to_hex(P)}")
    print(f"   Ciphertext: {bytes_to_hex(C)}")
    
    # Step 1: Reverse S-Box
    print(f"\n🔄 Step 1: Apply Inverse S-Box")
    E = apply_inverse_sbox(C)
    print(f"   Result (E): {bytes_to_hex(E)}")
    
    # Step 2: Reverse Rotation
    print(f"\n🔄 Step 2: Reverse Rotation (17 bits)")
    E_bits = bytes_to_bits(E)
    D_bits = rotate_bits(E_bits, 17, direction='left')
    D = bits_to_bytes(D_bits)
    print(f"   Result (D): {bytes_to_hex(D)}")
    
    # Step 3: XOR to get key
    print(f"\n🔄 Step 3: XOR with Plaintext to Get Key")
    K = xor_bytes(P, D)
    print(f"   Result (K): {bytes_to_hex(K)}")
    
    # Verify the key
    print(f"\n✅ Verification:")
    P_bits = bytes_to_bits(P)
    K_bits = bytes_to_bits(K)
    D_bits_verify = [p ^ k for p, k in zip(P_bits, K_bits)]
    E_bits_verify = rotate_bits(D_bits_verify, 17, direction='right')
    E_verify = bits_to_bytes(E_bits_verify)
    C_verify = apply_sbox(E_verify)
    
    if bytes_to_hex(C_verify) == bytes_to_hex(C):
        print(f"   ✓ Key verified successfully!")
        print(f"   Encrypting plaintext with key produces correct ciphertext")
    else:
        print(f"   ✗ Verification failed!")
        print(f"   Expected: {bytes_to_hex(C)}")
        print(f"   Got:      {bytes_to_hex(C_verify)}")
    
    print(f"\n{'=' * 60}")
    print(f"🔑 FINAL KEY: {bytes_to_hex(K)}")
    print(f"{'=' * 60}\n")
    
    return {
        'key': bytes_to_hex(K),
        'E': bytes_to_hex(E),
        'D': bytes_to_hex(D),
        'verified': bytes_to_hex(C_verify) == bytes_to_hex(C)
    }


def encrypt_sc1(plaintext_hex, key_hex):
    """
    Encrypt plaintext using SC-1 cipher (for verification)
    
    Args:
        plaintext_hex: Plaintext as hex string
        key_hex: Key as hex string
    
    Returns:
        Ciphertext as hex string
    """
    P = hex_to_bytes(plaintext_hex)
    K = hex_to_bytes(key_hex)
    
    # Step 1: XOR with key
    P_bits = bytes_to_bits(P)
    K_bits = bytes_to_bits(K)
    D_bits = [p ^ k for p, k in zip(P_bits, K_bits)]
    
    # Step 2: Rotate left 17 bits
    E_bits = rotate_bits(D_bits, 17, direction='right')
    E = bits_to_bytes(E_bits)
    
    # Step 3: Apply S-Box
    C = apply_sbox(E)
    
    return bytes_to_hex(C)


# Main execution
if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description='SC-1 cipher breaker (recover key from plaintext+ciphertext)')
    parser.add_argument('--plaintext', '-p', help='Plaintext as 16 hex digits (e.g. F5EF5D981B5DB510)')
    parser.add_argument('--ciphertext', '-c', help='Ciphertext as 16 hex digits (e.g. 2AAA8E541A37D5AF)')
    parser.add_argument('--quiet', '-q', action='store_true', help='Only print the final key')
    args = parser.parse_args()

    def is_valid_hex(s):
        if not s:
            return False
        s = s.replace(' ', '')
        if len(s) != 16:
            return False
        try:
            int(s, 16)
            return True
        except ValueError:
            return False

    # If both provided via CLI use them, else fall back to built-in sample and prompt the user
    if args.plaintext and args.ciphertext:
        if not is_valid_hex(args.plaintext) or not is_valid_hex(args.ciphertext):
            print('Error: plaintext and ciphertext must be 16 hex digits (spaces allowed).', file=sys.stderr)
            sys.exit(2)
        result = break_cipher(args.plaintext, args.ciphertext)
        if args.quiet:
            print(result['key'])
        sys.exit(0 if result['verified'] else 3)

    # Default sample from the project if no args supplied
    sample_pt = "F5EF5D981B5DB510"
    sample_ct = "2AAA8E541A37D5AF"
    print("Using sample data (from project):")
    result = break_cipher(sample_pt, sample_ct)

    # Prompt the user for optional input
    try:
        print("\nYou can try with different values (press Enter to skip):")
        user_pt = input("Enter plaintext (16 hex digits): ").strip()
        if user_pt:
            user_ct = input("Enter ciphertext (16 hex digits): ").strip()
            if not is_valid_hex(user_pt) or not is_valid_hex(user_ct):
                print('Invalid input: plaintext and ciphertext must be 16 hex digits (spaces allowed).')
            else:
                print()
                res2 = break_cipher(user_pt, user_ct)
                if args.quiet:
                    print(res2['key'])
    except KeyboardInterrupt:
        print("\n\nProgram terminated by user.")
    except Exception as e:
        print(f"\nError: {e}")