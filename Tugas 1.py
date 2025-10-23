IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

S_BOX = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

def permute(k, table):
    return "".join(k[i - 1] for i in table)

def xor(a, b):
    return "".join('1' if x != y else '0' for x, y in zip(a, b))

def text_to_binary(text):
    return ''.join(format(ord(c), '08b') for c in text)

def binary_to_bytes(binary):
    return bytes(int(binary[i:i+8], 2) for i in range(0, len(binary), 8))

def add_padding(text_bytes, block_size=8):
    padding_len = block_size - (len(text_bytes) % block_size)
    padding = bytes([padding_len] * padding_len)
    return text_bytes + padding

def remove_padding(padded_bytes):
    padding_len = padded_bytes[-1]
    if padding_len > 8 or padding_len == 0:
        raise ValueError("Invalid padding detected")
    return padded_bytes[:-padding_len]

def generate_subkeys(key_bin):
    key_56bit = permute(key_bin, PC1)
    C, D = key_56bit[:28], key_56bit[28:]
    subkeys = []
    for i in range(16):
        C = C[SHIFTS[i]:] + C[:SHIFTS[i]]
        D = D[SHIFTS[i]:] + D[:SHIFTS[i]]
        combined = C + D
        subkeys.append(permute(combined, PC2))
    return subkeys

def feistel_function(right_half, subkey):
    expanded_right = permute(right_half, E)
    xored = xor(expanded_right, subkey)
    s_box_output = ""
    for i in range(8):
        chunk = xored[i*6:(i+1)*6]
        row = int(chunk[0] + chunk[5], 2)
        col = int(chunk[1:5], 2)
        val = S_BOX[i][row][col]
        s_box_output += format(val, '04b')
    return permute(s_box_output, P)

def des_process(block_bin, subkeys, mode='encrypt'):
    permuted_block = permute(block_bin, IP)
    L, R = permuted_block[:32], permuted_block[32:]
    if mode == 'decrypt':
        subkeys = subkeys[::-1]
    for i in range(16):
        L_next = R
        R_next = xor(L, feistel_function(R, subkeys[i]))
        L, R = L_next, R_next
    combined = R + L
    return permute(combined, FP)

def des_encrypt(plaintext_str, key_str):
    key_bin = text_to_binary(key_str)
    subkeys = generate_subkeys(key_bin)
    
    plaintext_bytes = plaintext_str.encode('utf-8')
    padded_plaintext = add_padding(plaintext_bytes)
    
    encrypted_blocks_bytes = []
    
    for i in range(0, len(padded_plaintext), 8):
        block_bytes = padded_plaintext[i:i+8]
        block_bin = ''.join(format(byte, '08b') for byte in block_bytes)

        encrypted_block_bin = des_process(block_bin, subkeys, 'encrypt')
        encrypted_blocks_bytes.append(binary_to_bytes(encrypted_block_bin))
        
    return b''.join(encrypted_blocks_bytes)

def des_decrypt(ciphertext_bytes, key_str):
    key_bin = text_to_binary(key_str)
    subkeys = generate_subkeys(key_bin)
    
    decrypted_blocks_bytes = []

    for i in range(0, len(ciphertext_bytes), 8):
        block_bytes = ciphertext_bytes[i:i+8]
        block_bin = ''.join(format(byte, '08b') for byte in block_bytes)

        decrypted_block_bin = des_process(block_bin, subkeys, 'decrypt')
        decrypted_blocks_bytes.append(binary_to_bytes(decrypted_block_bin))

    padded_plaintext = b''.join(decrypted_blocks_bytes)
    original_plaintext = remove_padding(padded_plaintext)

    return original_plaintext.decode('utf-8')

def get_key():
    while True:
        key = input("Enter your 8-character secret key: ")
        if len(key) == 8:
            return key
        else:
            print("Error: Key must be exactly 8 characters long. Please try again.")

def handle_encryption():
    print("\n--- Encrypt a Message ---")
    plaintext = input("Enter the message to encrypt: ")
    key = get_key()
    try:
        ciphertext_bytes = des_encrypt(plaintext, key)
        ciphertext_hex = ciphertext_bytes.hex()
        print("\nEncryption Successful!")
        print(f"Ciphertext (hex): {ciphertext_hex}")
    except Exception as e:
        print(f"An error occurred during encryption: {e}")

def handle_decryption():
    print("\n--- Decrypt a Message ---")
    ciphertext_hex = input("Enter the ciphertext (hex): ")
    key = get_key()
    try:
        ciphertext_bytes = bytes.fromhex(ciphertext_hex)
        plaintext = des_decrypt(ciphertext_bytes, key)
        print("\nDecryption Successful!")
        print(f"Decrypted Message: {plaintext}")
    except ValueError:
        print("Error: Invalid hex input or incorrect key leading to padding error.")
    except Exception as e:
        print(f"An error occurred during decryption: {e}")

def main():
    while True:
        print("\n" + "="*30)
        print("   DES Encryptor/Decryptor")
        print("="*30)
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Exit")
        choice = input("Enter your choice (1, 2, or 3): ")

        if choice == '1':
            handle_encryption()
        elif choice == '2':
            handle_decryption()
        elif choice == '3':
            print("Exiting program...")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()