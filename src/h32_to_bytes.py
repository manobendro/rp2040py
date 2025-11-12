#!/usr/bin/env python3
"""
Convert bootrom.h32 file to Python bytes array.
Each line in the .h32 file contains a 32-bit hex value in little-endian format.
"""

def h32_to_bytes(input_file, output_file):
    """
    Convert .h32 file to Python bytes array.
    
    Args:
        input_file: Path to input .h32 file
        output_file: Path to output Python file
    """
    bytes_data = []
    
    # Read the .h32 file
    with open(input_file, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:  # Skip empty lines
                continue
            
            # Each line should be an 8-character hex string (32 bits)
            if len(line) != 8:
                print(f"Warning: Line {line_num} has unexpected length: '{line}'")
                continue
            
            try:
                # Parse hex string as little-endian 32-bit value
                # The data is already in little-endian format in the file
                hex_value = int(line, 16)
                
                # Convert to 4 bytes in little-endian order
                byte0 = hex_value & 0xFF
                byte1 = (hex_value >> 8) & 0xFF
                byte2 = (hex_value >> 16) & 0xFF
                byte3 = (hex_value >> 24) & 0xFF
                
                bytes_data.extend([byte0, byte1, byte2, byte3])
                
            except ValueError as e:
                print(f"Error parsing line {line_num}: '{line}' - {e}")
                continue
    
    # Write Python file with bytes array
    with open(output_file, 'w') as f:
        f.write("# Generated from bootrom.h32\n")
        f.write("# This is the RP2040 bootrom data as a bytes array\n\n")
        f.write("bootrom_data = bytes([\n")
        
        # Write bytes in rows of 16 for readability
        for i in range(0, len(bytes_data), 16):
            chunk = bytes_data[i:i+16]
            hex_values = ', '.join(f'0x{b:02X}' for b in chunk)
            f.write(f"    {hex_values},\n")
        
        f.write("])\n\n")
        f.write(f"# Total size: {len(bytes_data)} bytes\n")
    
    print(f"Converted {len(bytes_data)} bytes from {input_file} to {output_file}")
    return len(bytes_data)


if __name__ == "__main__":
    import sys
    
    # Default file paths
    input_file = "bootrom.h32"
    output_file = "bootrom_data.py"
    
    # Allow command line arguments
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    if len(sys.argv) > 2:
        output_file = sys.argv[2]
    
    try:
        size = h32_to_bytes(input_file, output_file)
        print(f"Success! Created {output_file} with {size} bytes")
    except FileNotFoundError:
        print(f"Error: Could not find input file '{input_file}'")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
