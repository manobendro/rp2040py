"""
RP2040 SIO (Single-cycle IO) peripheral emulation.

The SIO is located at 0xD0000000 and provides:
- CPUID register (identifies which core is running)
- GPIO controls
- Spinlocks
- Integer divider
- Interpolators
"""
from peripheral import Peripheral


class SIO(Peripheral):
    """
    SIO (Single-cycle IO) peripheral.
    
    Base address: 0xD0000000
    """
    
    # SIO Register offsets
    CPUID = 0x000          # Processor core identifier
    GPIO_IN = 0x004        # Input value for GPIO pins
    GPIO_HI_IN = 0x008     # Input value for QSPI pins
    GPIO_OUT = 0x010       # GPIO output value
    GPIO_OUT_SET = 0x014   # GPIO output value set
    GPIO_OUT_CLR = 0x018   # GPIO output value clear
    GPIO_OUT_XOR = 0x01C   # GPIO output value XOR
    GPIO_OE = 0x020        # GPIO output enable
    GPIO_OE_SET = 0x024    # GPIO output enable set
    GPIO_OE_CLR = 0x028    # GPIO output enable clear
    GPIO_OE_XOR = 0x02C    # GPIO output enable XOR
    
    # Size of SIO region
    SIO_SIZE = 0x180
    
    def __init__(self, base_address: int = 0xD0000000, core_id: int = 0):
        """
        Initialize SIO peripheral.
        
        Args:
            base_address: Base address (default 0xD0000000)
            core_id: CPU core ID (0 or 1, default 0)
        """
        super().__init__("SIO", base_address, self.SIO_SIZE)
        self.core_id = core_id
        
        # GPIO state
        self.gpio_out = 0
        self.gpio_oe = 0
    
    def read(self, offset: int, size: int) -> int:
        """Handle reads from SIO registers."""
        
        if offset == self.CPUID:
            # Return the core ID (0 for core 0, 1 for core 1)
            return self.core_id
        
        elif offset == self.GPIO_IN:
            # Return GPIO input value (stub: always 0)
            return 0
        
        elif offset == self.GPIO_HI_IN:
            # Return QSPI GPIO input value (stub: always 0)
            return 0
        
        elif offset == self.GPIO_OUT:
            return self.gpio_out
        
        elif offset == self.GPIO_OE:
            return self.gpio_oe
        
        else:
            return super().read(offset, size)
    
    def write(self, offset: int, size: int, value: int) -> None:
        """Handle writes to SIO registers."""
        
        if offset == self.CPUID:
            # CPUID is read-only, ignore writes
            pass
        
        elif offset == self.GPIO_OUT:
            self.gpio_out = value
        
        elif offset == self.GPIO_OUT_SET:
            self.gpio_out |= value
        
        elif offset == self.GPIO_OUT_CLR:
            self.gpio_out &= ~value
        
        elif offset == self.GPIO_OUT_XOR:
            self.gpio_out ^= value
        
        elif offset == self.GPIO_OE:
            self.gpio_oe = value
        
        elif offset == self.GPIO_OE_SET:
            self.gpio_oe |= value
        
        elif offset == self.GPIO_OE_CLR:
            self.gpio_oe &= ~value
        
        elif offset == self.GPIO_OE_XOR:
            self.gpio_oe ^= value
        
        else:
            super().write(offset, size, value)
