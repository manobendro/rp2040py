from unicorn import *
from unicorn.arm_const import *
from bootrom_data import bootrom_data
from sio import SIO
from resets import Resets
from clocks import Clocks

def scs_hook(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        print(f"SCS Write: 0x{address:08X} = 0x{value:08X}")
    else:
        print(f"SCS Read: 0x{address:08X}")
    return True

try:
    # code to be emulated: ADD R0, R1, R2
    # THUMB_CODE = b"\x88\x18\xc0\x46"  # machine code for: adds r0, r1, r2; nop
    THUMB_CODE = bootrom_data  # nop in Thumb mode

    # RP2040 Memory Map addresses
    ROM_ADDRESS = 0x00000000      # ROM
    XIP_ADDRESS = 0x10000000      # XIP (Execute-in-place flash)
    SRAM_ADDRESS = 0x20000000     # SRAM
    APB_ADDRESS = 0x40000000      # APB Peripherals
    AHB_ADDRESS = 0x50000000      # AHB-Lite Peripherals
    IOPORT_ADDRESS = 0xd0000000   # IOPORT Registers
    CORTEX_ADDRESS = 0xe0000000   # Cortex-M0+ internal registers
    
    # Legacy alias for compatibility
    RAM_ADDRESS = SRAM_ADDRESS

    print("Emulate ARM code")
    # Initialize emulator in ARM mode
    mu = Uc(UC_ARCH_ARM, UC_MODE_MCLASS | UC_MODE_LITTLE_ENDIAN)
    
    # Memory hook to trace instruction execution
    # mu.hook_add(UC_HOOK_CODE, lambda uc, address, size, user_data: print(f"\nExecuting instruction at 0x{address:X}, size: {size}, opcode: {uc.mem_read(address, size).hex()}"))

    # Hook to print all register values after each instruction
    def print_registers(uc):
        registers = {
            'R0': UC_ARM_REG_R0,
            'R1': UC_ARM_REG_R1,
            'R2': UC_ARM_REG_R2,
            'R3': UC_ARM_REG_R3,
            'R4': UC_ARM_REG_R4,
            'R5': UC_ARM_REG_R5,
            'R6': UC_ARM_REG_R6,
            'R7': UC_ARM_REG_R7,
            'R8': UC_ARM_REG_R8,
            'R9': UC_ARM_REG_R9,
            'R10': UC_ARM_REG_R10,
            'R11': UC_ARM_REG_R11,
            'R12': UC_ARM_REG_R12,
            'SP': UC_ARM_REG_SP,
            'LR': UC_ARM_REG_LR,
            'PC': UC_ARM_REG_PC,
        }
        print("Register values:")
        for name, reg in registers.items():
            print(f" {name}: 0x{uc.reg_read(reg):08X}", end=';')
        print('\n', end='')

    # mu.hook_add(UC_HOOK_CODE, lambda uc, address, size, user_data: print_registers(uc))
    
    # Memory hooks for peripheral regions
    def apb_hook(uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE:
            print(f"APB Write: 0x{address:08X} = 0x{value:08X}")
        else:
            print(f"APB Read: 0x{address:08X}")
        return True
    
    def ahb_hook(uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE:
            print(f"AHB Write: 0x{address:08X} = 0x{value:08X}")
        else:
            print(f"AHB Read: 0x{address:08X}")
        return True
    
    def ioport_hook(uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE:
            print(f"IOPORT Write: 0x{address:08X} = 0x{value:08X}")
        else:
            print(f"IOPORT Read: 0x{address:08X}")
        return True
    
    def cortex_hook(uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE:
            print(f"CORTEX Write: 0x{address:08X} = 0x{value:08X}")
        else:
            print(f"CORTEX Read: 0x{address:08X}")
        return True
    
    mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, apb_hook, 
                begin=APB_ADDRESS, end=APB_ADDRESS + 16*1024*1024)
    mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, ahb_hook, 
                begin=AHB_ADDRESS, end=AHB_ADDRESS + 16*1024*1024)
    mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, ioport_hook, 
                begin=IOPORT_ADDRESS, end=IOPORT_ADDRESS + 16*1024*1024)
    mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, cortex_hook, 
                begin=CORTEX_ADDRESS, end=CORTEX_ADDRESS + 1*1024*1024)
    
    # Create and register SIO peripheral
    sio = SIO(base_address=IOPORT_ADDRESS, core_id=0)
    
    # Create Resets peripheral
    resets = Resets(base_address=0x4000C000)
    
    # Create Clocks peripheral
    clocks = Clocks(base_address=0x40008000)
    
    # Map RP2040 memory regions according to the memory map
    mu.mem_map(ROM_ADDRESS, 16 * 1024)          # 0x00000000 - 16KB ROM
    mu.mem_map(XIP_ADDRESS, 16 * 1024 * 1024)   # 0x10000000 - 16MB XIP (flash)
    mu.mem_map(SRAM_ADDRESS, 264 * 1024)        # 0x20000000 - 264KB SRAM
    mu.mem_map(APB_ADDRESS, 16 * 1024 * 1024)   # 0x40000000 - APB Peripherals
    mu.mem_map(AHB_ADDRESS, 16 * 1024 * 1024)   # 0x50000000 - AHB-Lite Peripherals
    mu.mem_map(IOPORT_ADDRESS, 16 * 1024 * 1024)# 0xd0000000 - IOPORT Registers
    mu.mem_map(CORTEX_ADDRESS, 1 * 1024 * 1024) # 0xe0000000 - Cortex-M0+ internal registers

    # Register SIO peripheral hooks (must be after mem_map)
    sio.register_hooks(mu)
    
    # Register Resets peripheral hooks
    resets.register_hooks(mu)
    
    # Register Clocks peripheral hooks
    clocks.register_hooks(mu)

    # write machine code to be emulated to memory
    mu.mem_write(ROM_ADDRESS, THUMB_CODE)

    # Extract SP and PC values from bootrom_data
    sp_value = int.from_bytes(bootrom_data[:4], "little")  # First 4 bytes
    pc_value = int.from_bytes(bootrom_data[4:8], "little")  # Next 4 bytes

    # Set the program counter and stack pointer
    mu.reg_write(UC_ARM_REG_PC, pc_value)
    mu.reg_write(UC_ARM_REG_SP, sp_value)
    
    # initialize machine registers
    mu.reg_write(UC_ARM_REG_R1, 5)  # R1 = 5
    mu.reg_write(UC_ARM_REG_R2, 10) # R2 = 10

    # emulate code in infinite time & unlimited instructions
    mu.emu_start(pc_value, ROM_ADDRESS + len(THUMB_CODE))

    # now print out some registers
    r0 = mu.reg_read(UC_ARM_REG_R0)
    print("Emulation done. R0 = %d" % r0)  # should print 15
except UcError as e:
    print("ERROR: %s" % e)
    