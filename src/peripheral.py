"""
Base class for RP2040 peripheral emulation.
"""
from unicorn import *


class Peripheral:
    """Base class for all RP2040 peripherals."""
    
    def __init__(self, name: str, base_address: int, size: int):
        """
        Initialize a peripheral.
        
        Args:
            name: Human-readable name for the peripheral
            base_address: Base address of the peripheral in memory
            size: Size of the peripheral's memory region in bytes
        """
        self.name = name
        self.base_address = base_address
        self.size = size
    
    def read(self, offset: int, size: int) -> int:
        """
        Handle a read from the peripheral.
        
        Args:
            offset: Offset from base address
            size: Number of bytes to read (1, 2, or 4)
            
        Returns:
            Value read from the peripheral
        """
        print(f"[{self.name}] Unhandled read at offset 0x{offset:04X} (size={size})")
        return 0
    
    def write(self, offset: int, size: int, value: int) -> None:
        """
        Handle a write to the peripheral.
        
        Args:
            offset: Offset from base address
            size: Number of bytes to write (1, 2, or 4)
            value: Value to write
        """
        print(f"[{self.name}] Unhandled write at offset 0x{offset:04X} = 0x{value:X} (size={size})")
    
    def register_hooks(self, uc: Uc) -> None:
        """
        Register memory hooks with Unicorn for this peripheral.
        
        Args:
            uc: Unicorn instance
        """
        def hook_callback(uc, access, address, size, value, user_data):
            offset = address - self.base_address
            if access == UC_MEM_WRITE:
                self.write(offset, size, value)
            else:
                result = self.read(offset, size)
                # Write the result back to memory so Unicorn can read it
                uc.mem_write(address, result.to_bytes(size, 'little'))
            return True
        
        uc.hook_add(
            UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
            hook_callback,
            begin=self.base_address,
            end=self.base_address + self.size
        )
