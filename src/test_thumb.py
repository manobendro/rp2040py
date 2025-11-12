from unicorn import *
from unicorn.arm_const import *

# Initialize Unicorn for ARM Thumb mode (common for Cortex-M)
mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

# Map memory (e.g., 0x0 for code, 0x1000 for stack)
ADDRESS = 0x00000000
SIZE = 16 * 1024  # 16 KB
mu.mem_map(ADDRESS, SIZE)

# Load your ARM M-class binary code into memory
# For example, a simple instruction sequence
CODE = b"\x88\x18\x00\xBF" # Example: ADD R0, R1, R2; NOP;

# code = [
#     b"\x00\xb5", # PUSH {LR}
#     b"\x00\xbf", # NOP
# ]

mu.mem_write(ADDRESS, CODE)

# Set the program counter
mu.reg_write(UC_ARM_REG_PC, ADDRESS)

# Set the stack pointer
mu.reg_write(UC_ARM_REG_SP, ADDRESS + SIZE - 4) # Example: End of mapped memory

# Memory hook to trace instruction execution
mu.hook_add(UC_HOOK_CODE, lambda uc, address, size, user_data: print(f"Executing instruction at 0x{address:X}, size: {size}, opcode: {uc.mem_read(address, size).hex()}"))

# # Extract SP and PC values from bootrom_data
# sp_value = int.from_bytes(bootrom_data[:4], "little")  # First 4 bytes
# pc_value = int.from_bytes(bootrom_data[4:8], "little")  # Next 4 bytes

# # Set the program counter and stack pointer
# mu.reg_write(UC_ARM_REG_PC, pc_value)
# mu.reg_write(UC_ARM_REG_SP, sp_value)

# write initial register values if needed
mu.reg_write(UC_ARM_REG_R1, 0x4)
mu.reg_write(UC_ARM_REG_R2, 0x4)

# Start emulation
try:
    mu.emu_start(ADDRESS | 0x1, ADDRESS + len(CODE))
except UcError as e:
    print(f"Emulation error: {e}")

# Read register values after emulation
pc_value = mu.reg_read(UC_ARM_REG_PC)
r0_value = mu.reg_read(UC_ARM_REG_R0)
print(f"Final PC: {hex(pc_value)}, R0: {hex(r0_value)}")