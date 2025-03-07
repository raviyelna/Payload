from z3 import *
import string

# Constants from the problem
ENCODING_TABLE = '0#23WXYZ89BCDFGHJKLMNPQR$TV@567!1111111144444444'
output = [
    51, 66, 81, 87, 80, 48, 75, 56, 35, 76, 78, 86, 76, 81, 88,
    68, 68, 64, 54, 50, 89, 84, 80, 68, 70, 35, 76, 66, 88, 90,
    75, 66, 75, 75, 77, 71, 87, 77, 87, 56, 71, 66, 74, 36, 78,
    68, 70, 66, 75, 84, 78
]

# Convert the output to characters
output_chars = [chr(x) for x in output]

# Reverse mapping: character to position in ENCODING_TABLE
encoding_map = {char: idx for idx, char in enumerate(ENCODING_TABLE)}

def decode_chunk(chunk):
    """
    Decode a chunk of the output based on the reversed algorithm from the disassembly
    """
    # Map characters to their indices in the encoding table
    indices = [encoding_map.get(char, -1) for char in chunk]
    
    # Skip invalid chunks
    if -1 in indices:
        return None
    
    # Reverse the mapping from the assembly code
    if len(indices) >= 1:
        b0 = indices[0]
    else:
        return None
        
    if len(indices) >= 2:
        b1 = indices[1]
    else:
        return None
        
    if len(indices) >= 3:
        b2 = indices[2]
    else:
        return None
        
    if len(indices) >= 4:
        b3 = indices[3]
    else:
        return None
        
    if len(indices) >= 5:
        b4 = indices[4]
    else:
        return None
    
    if len(indices) >= 6:
        b5 = indices[5]
    else:
        return None
    
    if len(indices) >= 7:
        b6 = indices[6]
    else:
        return None
    
    if len(indices) >= 8:
        b7 = indices[7]
    else:
        b7 = 0  # Default if not enough characters
    
    # Reconstruct the original bytes using Z3
    solver = Solver()
    
    # Create 5 bitvector variables for the original bytes
    orig_bytes = [BitVec(f'b{i}', 8) for i in range(5)]
    
    # Add constraints based on the encoding algorithm
    # v12[0] = v13 & 0x1F;
    solver.add(Extract(4, 0, orig_bytes[0]) == b0)
    
    # v12[1] = (v13 >> 5) | (8 * (v14 & 3));
    solver.add(Concat(Extract(7, 5, orig_bytes[0]), Extract(1, 0, orig_bytes[1]) * 8) == b1)
    
    # v12[2] = (v14 >> 2) & 0x1F;
    solver.add(Extract(6, 2, orig_bytes[1]) == b2)
    
    # v12[3] = (v14 >> 7) | (2 * (v15 & 0xF));
    solver.add(Concat(Extract(7, 7, orig_bytes[1]), Extract(3, 0, orig_bytes[2]) * 2) == b3)
    
    # v12[4] = (v15 >> 4) | (16 * (v16 & 1));
    solver.add(Concat(Extract(7, 4, orig_bytes[2]), Extract(0, 0, orig_bytes[3]) * 16) == b4)
    
    # v12[5] = (v16 >> 1) & 0x1F;
    solver.add(Extract(5, 1, orig_bytes[3]) == b5)
    
    # v12[6] = (v16 >> 6) | (4 * (v17 & 7));
    solver.add(Concat(Extract(7, 6, orig_bytes[3]), Extract(2, 0, orig_bytes[4]) * 4) == b6)
    
    # v12[7] = v17 >> 3;
    solver.add(Extract(7, 3, orig_bytes[4]) == b7)
    
    # Add constraints for printable ASCII
    for b in orig_bytes:
        solver.add(b >= 32, b <= 126)
    
    if solver.check() == sat:
        model = solver.model()
        result = bytes([model.evaluate(b).as_long() for b in orig_bytes])
        return result
    
    return None

def solve_message():
    """
    Attempt to solve the entire encoded message
    """
    decoded_bytes = bytearray()
    
    # Process the output in chunks of 8 (or less for the last chunk)
    i = 0
    while i < len(output_chars):
        # Determine chunk size based on remaining characters
        remaining = len(output_chars) - i
        chunk_size = min(8, remaining)
        
        # Extract the chunk
        chunk = output_chars[i:i+chunk_size]
        
        # Try to decode
        decoded = decode_chunk(chunk)
        if decoded:
            decoded_bytes.extend(decoded)
        
        # Move to the next potential chunk
        # Chunk sizes follow the pattern in the switch statement: 2, 3, 5, 7, or 8
        if chunk_size <= 2:
            i += 2  # For 1 original byte
        elif chunk_size <= 3:
            i += 3  # For 2 original bytes
        elif chunk_size <= 5:
            i += 5  # For 3 original bytes
        elif chunk_size <= 7:
            i += 7  # For 4 original bytes
        else:
            i += 8  # For 5 original bytes
    
    return decoded_bytes

# Alternative approach using direct reverse engineering
def direct_decode():
    """
    Directly reverse the encoding algorithm without using Z3
    """
    def bytes_to_5bit(byte_array):
        """Convert 5 bytes into 8 5-bit values as described in the algorithm"""
        v13, v14, v15, v16, v17 = byte_array[0:5] if len(byte_array) >= 5 else byte_array + bytes([0] * (5 - len(byte_array)))
        
        v12 = [0] * 8
        v12[0] = v13 & 0x1F
        v12[1] = (v13 >> 5) | (8 * (v14 & 3))
        v12[2] = (v14 >> 2) & 0x1F
        v12[3] = (v14 >> 7) | (2 * (v15 & 0xF))
        v12[4] = (v15 >> 4) | (16 * (v16 & 1))
        v12[5] = (v16 >> 1) & 0x1F
        v12[6] = (v16 >> 6) | (4 * (v17 & 7))
        v12[7] = v17 >> 3
        
        return v12
    
    # Loop through possible byte patterns and find ones that match the output
    decoded = bytearray()
    i = 0
    
    while i < len(output):
        for test_length in range(1, 6):  # Try 1-5 bytes
            # Create test bytes
            for test_bytes in itertools.product(range(32, 127), repeat=test_length):
                test_arr = bytes(test_bytes)
                five_bit = bytes_to_5bit(test_arr)
                
                # Calculate n2 based on the switch statement
                if test_length == 1:
                    n2 = 2
                elif test_length == 2:
                    n2 = 3
                elif test_length == 3:
                    n2 = 5
                elif test_length == 4:
                    n2 = 7
                else:
                    n2 = 8
                
                # Check if encoding matches the output
                matches = True
                for j in range(min(n2, len(output) - i)):
                    encoded_char = ENCODING_TABLE[five_bit[j]]
                    if ord(encoded_char) != output[i + j]:
                        matches = False
                        break
                
                if matches:
                    decoded.extend(test_arr)
                    i += n2
                    break
            else:
                continue
            break
        else:
            # If no match is found, skip this character
            i += 1
    
    return decoded

# Brute force approach 
def decode_brute_force():
    result = ""
    i = 0
    
    # Process the output in chunks based on the assembly logic
    while i < len(output_chars):
        remaining = len(output_chars) - i
        
        # Determine the chunk size (n2) based on the switch statement
        if remaining == 1:
            chunk_size = 2
        elif remaining == 2:
            chunk_size = 3
        elif remaining == 3:
            chunk_size = 5
        elif remaining == 4:
            chunk_size = 7
        else:
            chunk_size = 8
            
        chunk_size = min(chunk_size, remaining)
        chunk = output_chars[i:i+chunk_size]
        
        # Try all possible 5-byte combinations and check if they encode to our chunk
        # This is a simplified approach for demonstration
        # In a real solution, you'd want to optimize this search
        
        i += chunk_size
    
    return result

# Simplified custom solver based on the encoding algorithm
def custom_decoder():
    # Maps from encoding table indices back to bytes
    def reverse_map(indices):
        # Reconstruct the original bytes from the 5-bit encoding
        if len(indices) < 2:
            return b''
        
        result = bytearray()
        
        # Handle first byte (from indices 0 and 1)
        byte1 = (indices[0] & 0x1F) | ((indices[1] & 0x7) << 5)
        result.append(byte1)
        
        if len(indices) < 3:
            return bytes(result)
            
        # Handle second byte (from indices 1, 2, and 3)
        byte2 = ((indices[1] >> 3) & 0x3) | ((indices[2] & 0x1F) << 2) | ((indices[3] & 0x1) << 7)
        result.append(byte2)
        
        if len(indices) < 5:
            return bytes(result)
            
        # Handle third byte (from indices 3 and 4)
        byte3 = ((indices[3] >> 1) & 0xF) | ((indices[4] & 0xF) << 4)
        result.append(byte3)
        
        if len(indices) < 6:
            return bytes(result)
            
        # Handle fourth byte (from indices 4, 5, and 6)
        byte4 = ((indices[4] >> 4) & 0x1) | ((indices[5] & 0x1F) << 1) | ((indices[6] & 0x3) << 6)
        result.append(byte4)
        
        if len(indices) < 8:
            return bytes(result)
            
        # Handle fifth byte (from indices 6 and 7)
        byte5 = ((indices[6] >> 2) & 0x7) | ((indices[7] & 0x1F) << 3)
        result.append(byte5)
        
        return bytes(result)
    
    # Process the output in chunks
    decoded = bytearray()
    i = 0
    
    while i < len(output_chars):
        # Determine chunk size based on remaining bytes
        remaining = len(output_chars) - i
        
        if remaining == 1:
            chunk_size = 1  # Should be 2, but we only have 1 left
        elif remaining == 2:
            chunk_size = 2  # Should be 2 for 1 byte
        elif remaining == 3:
            chunk_size = 3  # 3 for 2 bytes
        elif remaining == 4:
            chunk_size = 4  # Should be 5, but we only have 4 left
        elif remaining <= 7:
            chunk_size = min(remaining, 5)  # Should handle both 5 and 7 cases
        else:
            chunk_size = 8  # 8 for 5 bytes
        
        # Get indices from encoding table
        chunk = output_chars[i:i+chunk_size]
        indices = [encoding_map.get(c, 0) for c in chunk]
        
        # Decode chunk
        decoded_chunk = reverse_map(indices)
        if decoded_chunk:
            decoded.extend(decoded_chunk)
        
        # Move to the next chunk
        i += chunk_size
    
    # Try to interpret as ASCII
    try:
        return decoded.decode('ascii')
    except:
        return decoded

# Use a simpler, more direct approach based on the encoding algorithm
def decode_custom():
    result = []
    i = 0
    
    while i < len(output):
        # Get indices for the current chunk
        indices = []
        remaining = len(output) - i
        
        # Determine the number of characters to process based on the switch statement
        if remaining == 1:
            n2 = 1  # Should be 2, but we only have 1
        elif remaining == 2:
            n2 = 2  # Should encode 1 byte
        elif remaining == 3:
            n2 = 3  # Should encode 2 bytes
        elif remaining == 4:
            n2 = 4  # Should be 5, but we only have 4
        elif remaining >= 5 and remaining < 7:
            n2 = 5  # Should encode 3 bytes
        elif remaining == 7:
            n2 = 7  # Should encode 4 bytes
        else:
            n2 = 8  # Should encode 5 bytes
            
        n2 = min(n2, remaining)
        
        # Get the encoding indices
        for j in range(n2):
            char = chr(output[i + j])
            if char in ENCODING_TABLE:
                indices.append(ENCODING_TABLE.index(char))
            else:
                indices.append(0)  # Default if character not found
        
        # Reverse the encoding algorithm to get the original bytes
        if len(indices) >= 2:
            # Extract first byte from indices 0 and 1
            byte1 = (indices[0] & 0x1F) | ((indices[1] & 0x7) << 5)
            result.append(byte1)
            
        if len(indices) >= 3:
            # Extract second byte from indices 1, 2, and potentially 3
            if len(indices) >= 4:
                byte2 = ((indices[1] >> 3) & 0x3) | ((indices[2] & 0x1F) << 2) | ((indices[3] & 0x1) << 7)
            else:
                byte2 = ((indices[1] >> 3) & 0x3) | ((indices[2] & 0x1F) << 2)
            result.append(byte2)
            
        if len(indices) >= 5:
            # Extract third byte from indices 3 and 4
            byte3 = ((indices[3] >> 1) & 0xF) | ((indices[4] & 0xF) << 4)
            result.append(byte3)
            
        if len(indices) >= 6:
            # Extract fourth byte from indices 4, 5, and 6
            byte4 = ((indices[4] >> 4) & 0x1) | ((indices[5] & 0x1F) << 1) | ((indices[6] & 0x3) << 6)
            result.append(byte4)
            
        if len(indices) >= 8:
            # Extract fifth byte from indices 6 and 7
            byte5 = ((indices[6] >> 2) & 0x7) | ((indices[7] & 0x1F) << 3)
            result.append(byte5)
            
        # Move to next chunk
        i += n2
    
    # Try to convert the bytes to ASCII
    try:
        return ''.join(chr(b) for b in result if 32 <= b <= 126)
    except:
        return result

# Final simplified approach - most direct reverse engineering
def decode_final():
    # For each character in the output, find its index in the encoding table
    indices = []
    for char_code in output:
        char = chr(char_code)
        if char in ENCODING_TABLE:
            indices.append(ENCODING_TABLE.index(char))
        else:
            indices.append(0)  # Default if not found
    
    # Now reverse the encoding process in groups
    result = bytearray()
    i = 0
    
    while i < len(indices):
        if i + 1 < len(indices):
            # First byte from indices 0 and 1
            byte1 = (indices[i] & 0x1F) | ((indices[i+1] & 0x7) << 5)
            result.append(byte1)
        
        if i + 2 < len(indices):
            # Second byte from indices 1, 2, and 3
            if i + 3 < len(indices):
                byte2 = ((indices[i+1] >> 3) & 0x3) | ((indices[i+2] & 0x1F) << 2) | ((indices[i+3] & 0x1) << 7)
            else:
                byte2 = ((indices[i+1] >> 3) & 0x3) | ((indices[i+2] & 0x1F) << 2)
            result.append(byte2)
        
        if i + 4 < len(indices):
            # Third byte from indices 3 and 4
            byte3 = ((indices[i+3] >> 1) & 0xF) | ((indices[i+4] & 0xF) << 4)
            result.append(byte3)
        
        if i + 6 < len(indices):
            # Fourth byte from indices 4, 5, and 6
            byte4 = ((indices[i+4] >> 4) & 0x1) | ((indices[i+5] & 0x1F) << 1) | ((indices[i+6] & 0x3) << 6)
            result.append(byte4)
        
        if i + 7 < len(indices):
            # Fifth byte from indices 6 and 7
            byte5 = ((indices[i+6] >> 2) & 0x7) | ((indices[i+7] & 0x1F) << 3)
            result.append(byte5)
            i += 8
        elif i + 6 < len(indices):
            i += 7
        elif i + 4 < len(indices):
            i += 5
        elif i + 2 < len(indices):
            i += 3
        elif i + 1 < len(indices):
            i += 2
        else:
            i += 1
    
    # Try to interpret as ASCII
    try:
        return result.decode('ascii')
    except:
        # If it fails, return printable chars
        return ''.join(chr(b) for b in result if 32 <= b <= 126)

# Try the final direct decoding approach
print("Decoded message:", decode_final())

# If you want to use Z3-based approach, uncomment the following:
# print("Decoded with Z3:", solve_message().decode('ascii', errors='replace'))