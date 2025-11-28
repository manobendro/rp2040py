"""
RP2040 RESETS peripheral emulation.

The RESETS peripheral controls reset state of various peripherals.
Base address: 0x4000C000
"""
from peripheral import Peripheral


class Resets(Peripheral):
    """
    RESETS peripheral.
    
    Base address: 0x4000C000
    
    Controls the reset state of peripherals. Writing 1 to a bit in RESET
    holds that peripheral in reset. RESET_DONE shows which peripherals
    have completed their reset sequence.
    """
    
    # Register offsets
    RESET = 0x0           # Reset control
    WDSEL = 0x4           # Watchdog select
    RESET_DONE = 0x8      # Reset done status
    
    # Size of RESETS region
    RESETS_SIZE = 0x10
    
    # Peripheral bit definitions (bits 0-24)
    PERIPHERAL_BITS = {
        0: "adc",
        1: "busctrl",
        2: "dma",
        3: "i2c0",
        4: "i2c1",
        5: "io_bank0",
        6: "io_qspi",
        7: "jtag",
        8: "pads_bank0",
        9: "pads_qspi",
        10: "pio0",
        11: "pio1",
        12: "pll_sys",
        13: "pll_usb",
        14: "pwm",
        15: "rtc",
        16: "spi0",
        17: "spi1",
        18: "syscfg",
        19: "sysinfo",
        20: "tbman",
        21: "timer",
        22: "uart0",
        23: "uart1",
        24: "usbctrl",
    }
    
    def __init__(self, base_address: int = 0x4000C000):
        """
        Initialize RESETS peripheral.
        
        Args:
            base_address: Base address (default 0x4000C000)
        """
        super().__init__("RESETS", base_address, self.RESETS_SIZE)
        
        # Reset control register - all peripherals start in reset (all bits set)
        self.reset = 0x00000000  # Bits 0-24 set
        
        # Watchdog select - which peripherals are reset by watchdog
        self.wdsel = 0x00000000
        
    def _get_reset_done(self) -> int:
        """
        Calculate RESET_DONE based on current RESET state.
        Peripherals not in reset (bit=0 in RESET) are done (bit=1 in RESET_DONE).
        """
        # Invert: if reset bit is 0, peripheral is out of reset, so done bit is 1
        return (~self.reset) & 0x01FFFFFF
    
    def read(self, offset: int, size: int) -> int:
        """Handle reads from RESETS registers."""
        
        if offset == self.RESET:
            return self.reset
        
        elif offset == self.WDSEL:
            return self.wdsel
        
        elif offset == self.RESET_DONE:
            return self._get_reset_done()
        
        else:
            return super().read(offset, size)
    
    def write(self, offset: int, size: int, value: int) -> None:
        """Handle writes to RESETS registers."""
        
        if offset == self.RESET:
            self.reset = value & 0x01FFFFFF
        
        elif offset == self.WDSEL:
            self.wdsel = value & 0x01FFFFFF
        
        elif offset == self.RESET_DONE:
            # RESET_DONE is read-only, ignore writes
            pass
        
        else:
            super().write(offset, size, value)
