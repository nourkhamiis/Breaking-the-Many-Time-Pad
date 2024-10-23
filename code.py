# ----------------------------------------------------------------------------------------------------------------------------------------------
from collections import Counter
# ----------------------------------------------------------------------------------------------------------------------------------------------

ciphers = [
    "F9B4228898864FCB32D83F3DFD7589F109E33988FA8C7A9E9170FB923065F52DD648AA2B8359E1D122122738A8B9998BE278B2BD7CF3313C7609",
    "F5BF229F8F9B1C8832C0212DFD7F92EA18FF29C7E6C968848D6EFAC16074F129D640AB67CE59E3DC6109212AB4EB959FFD34F3B269EB292C7409",
    "FDAF668499C801C734813F3BF3718FF91AEA2C88FC862B999D6EE7C16369F83ADF57FF28CD18FCCC6F0D2B2BB5A295DEF436B0A164EF3C267014",
    "FDFB35858B8403882EC4392CE03289F50CF82588FC816ECB8B63F3843076F52CC059B035C718E0DB220D3B33B3A28692F478B2B07EF03D216B09",
    "E4BE239FCA9A0ADE29C43869FD74DBE31CE835DAE19D72CB9567FD897168FD2CDE5DFF35C65CFAD667136E29B2A7989BE339B1BA71F63C267A09",
    "F8BE279F848101CF60C9203EB26694B00EF929DCEDC9788E9B77EC843075FB39C759BE35C618E6C622016E31A2A8938DE239A1AA3DEC23267316",
    "E7BE2598988D4FC325D86F2CEA7193F117EC2588E19A2B859D67FA847426F230C10EAC3ECE55EAC170092D7FACAE8FDEF436B0A164EF3C267014",
    "E7BE259898811BD160C03B69E67A9EB01CF330CDE69A6ECB9764BE946367F636DF47AB3E835BE0C06E046E3BA6A69799F478A0B67EEA3A266B03" 
]

# ----------------------------------------------------------------------------------------------------------------------------------------------

# Changing the hex strings to bytes to be able to perform XOR operations
cipher_bytes = []
for c in ciphers:
    byte = bytes.fromhex(c)
    cipher_bytes.append(byte)

# Saving the length of the ciphertexts (ALL HAVE SAME LENGTH)
LENGTH = len(cipher_bytes[0])

KEY = bytearray([ord('*')] * LENGTH)

# Initializing the plaintexts as empty byte arrays
PLAINTEXTS = []
for i in range(8):
    PLAINTEXTS.append(bytearray(LENGTH))

# ----------------------------------------------------------------------------------------------------------------------------------------------

# This function takes a byte stream and returns a string of the correspinding ASCII characters (only printable ASCII characters)
def hex_to_string(byte_stream):
    ascii_string = ""
    for b in byte_stream:
        # We need to check if the byte represents a printable character (32: ' ' --to--> 126: '~')
        if 32 <= b <= 126:
            ascii_string += chr(b)
        else:
            ascii_string += '*'
    return ascii_string

# ----------------------------------------------------------------------------------------------------------------------------------------------

def string_to_hex(ascii_string):
    byte_array = bytearray()
    for char in ascii_string:
        if 32 <= ord(char) <= 126:
            byte_array.append(ord(char))
        else:
            byte_array.append(ord('*'))
    return byte_array

# ---------------------------------------------------------------------------------------------------------------------------------------------

# This function performs XOR on each 2 ciphertexts represented as bytes and the result is represented as bytes
def xor_bytes(b1, b2):
    # zip functions will create an array of tuples of each 2 bytes
    # print (list(zip(b1,b2)))
    byte_tuples = zip(b1,b2)
    result = bytes([x ^ y for x, y in byte_tuples])
    return result

# ---------------------------------------------------------------------------------------------------------------------------------------------

# This function returns an array of all possibilities of space ' ' positions for two ciphers c1 and c2
# It takes the indices of the ciphers as parameters
def possible_space_positions_for_ciphers(c1,c2):
    positions = []
    cipher1 = cipher_bytes[c1]
    cipher2 = cipher_bytes[c2]
    xor_res = xor_bytes(cipher1, cipher2)
    # print(f"\nciphertext {c} XOR ciphertext {i}")
    for j,byte in enumerate(xor_res):
        # print(byte , end=' ') # This prints the xor result bytes (in decimal)
        if (byte>=65 and byte <=90) or (byte>=97 and byte <=122):
            # This means that this is an ascii code for a letter
            # Therefore, possible position for a space
            positions.append(j)
    return positions

# ---------------------------------------------------------------------------------------------------------------------------------------------

# This returns the indices of the positions where it is most likely to be a space in the plaintext corresponding to a cipher
# The threshold for the most common is chosen to be (>3) , since we compare c to 7 other ciphers
def common_space_positions_for_cipher(c):
    # print(f"Analyzing Ciphertext {c} ..")
    space_positions = []
    
    for i in range(8):
        if i == c:
            continue
        space_pos = possible_space_positions_for_ciphers(c, i)
        space_positions.append(space_pos)

        # print(f"Possible Spaces of {c} and {i} are: ", space_pos)

    all_positions = []
    for positions in space_positions:
        for pos in positions:
            all_positions.append(pos)
    
    position_counts = Counter(all_positions)

    common_spaces = []
    for pos, count in position_counts.items():
        # Knowing that we compare each cipher to 7 other ciphers, I chose the threshold to be ">3"
        # To ensure that the space in the ciphertext appeared in at least half of the comparisons
        if count > 3:
            common_spaces.append(pos)

    # print(f"\nCommon Space Positions for Ciphertext {c}: ",common_spaces, "\n")
            
    return common_spaces

# ---------------------------------------------------------------------------------------------------------------------------------------------

# This function modifies the plaintexts to have _ in the positions of spaces
def update_plaintexts_with_spaces():
    global PLAINTEXTS
    for c in range(8):
        space_positions = common_space_positions_for_cipher(c)
        for pos in space_positions:
            # plaintext at that position will be replaced with ASCII of '_'
            PLAINTEXTS[c][pos] = ord('_')

    # print("\nUpdates plaintexts (spaces are represented as '_'):\n")
    # for i, _ in enumerate(plaintexts):
    #     print(bytes_to_ascii(plaintexts[i]))

# ---------------------------------------------------------------------------------------------------------------------------------------------

# This function predict the initial key based on the space positions in each cipher
def update_key_knowing_spaces(c):
    global KEY
    positions = common_space_positions_for_cipher(c)
    cipher = cipher_bytes[c]
    for pos in positions:
        KEY[pos] = cipher[pos] ^ 0x20
    
    # print(f"\n\nUpdated key knowing space positions for cipher {c} :\n")
    # print(bytes_to_ascii(KEY), "\n")

# ---------------------------------------------------------------------------------------------------------------------------------------------

# This function updates all plaintexts by XORing them with the current global KEY, it's called everytime we modify the key
def update_plaintexts_using_key():
    global KEY,PLAINTEXTS
    for c in range(0,8):
        for pos,k in enumerate(KEY):
            if k != ord('*'):
                PLAINTEXTS[c][pos] = cipher_bytes[c][pos] ^ k
            else:
                PLAINTEXTS[c][pos] = ord('*')
        print(f"P{c}: ",hex_to_string(PLAINTEXTS[c]))
    
# ---------------------------------------------------------------------------------------------------------------------------------------------

# This reveals parts of the messages, which are clear before any GUESSing (as a result of space position determining)
def first_guess_knowing_spaces():
    for i in range(0,8):    
        update_key_knowing_spaces(i)
        update_plaintexts_using_key()
        print("  ")
        
# ---------------------------------------------------------------------------------------------------------------------------------------------

# This function only updates the key at certain positions starting from x to y
def update_key_and_plaintext(p,c,x,y):
    global KEY, PLAINTEXTS
    PLAINTEXTS[c] = string_to_hex(p)
    new_key = xor_bytes(PLAINTEXTS[c][x:y] , cipher_bytes[c][x:y])
    KEY[x:y] = new_key
    
# ---------------------------------------------------------------------------------------------------------------------------------------------

if __name__ == "__main__":
    
    update_plaintexts_with_spaces()
    
    first_guess_knowing_spaces()
    
    print(">> ITERATION 1\n")
    update_plaintexts_using_key()
    
    # Starting from Iteration #2, the approach of EDUCATED GUESSES is Used
    
    print("\n\n>> ITERATION 2\n")
    plaintext0 = "modern cryptography requires careful a** *ig*r*u* a*a*****"
    update_key_and_plaintext(plaintext0,0,0,36)
    update_plaintexts_using_key()
    
    print("\n\n>> ITERATION 3\n")
    plaintext6 = "secure key exchange is needed for symmetric key encryption"
    update_key_and_plaintext(plaintext6,6,0,58)
    update_plaintexts_using_key()
    
    
    print(f"\n\nThe final hex key is: \n{KEY}")
    
  # ---------------------------------------------------------------------------------------------------------------------------------------------  