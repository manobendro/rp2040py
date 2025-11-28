"""
RP2040 XOSC (Crystal Oscillator) peripheral emulation.

The XOSC peripheral controls the external crystal oscillator.
Base address: 0x40024000
"""
from peripheral import Peripheral


class XOSC(Peripheral):
    """
    XOSC (Crystal Oscillator) peripheral.
    
    Base address: 0x40024000
    
    Controls the external crystal oscillator for stable clock generation.
    """
    
    # Register offsets
    CTRL = 0x00           # Crystal Oscillator Control
    STATUS = 0x04         # Crystal Oscillator Status
    DORMANT = 0x08        # Crystal Oscillator pause control
    STARTUP = 0x0C        # Controls the startup delay
    COUNT = 0x1C          # Down counter running at XOSC frequency
    
    # Size of XOSC region
    XOSC_SIZE = 0x20
    
    # CTRL register fields
    CTRL_ENABLE_DISABLE = 0xD1E
    CTRL_ENABLE_ENABLE = 0xFAB
    
    # STATUS register bits
    STATUS_STABLE = (1 << 31)    # Oscillator is running and stable
    STATUS_BADWRITE = (1 << 24)  # Bad write to CTRL register
    STATUS_ENABLED = (1 << 12)   # Oscillator is enabled
    STATUS_FREQ_RANGE = 0x3      # Frequency range (bits 1:0)
    
    def __init__(self, base_address: int = 0x40024000):
        """
        Initialize XOSC peripheral.
        
        Args:
            base_address: Base address (default 0x40024000)
        """
        super().__init__("XOSC", base_address, self.XOSC_SIZE)
        
        # Control register
        self.ctrl = 0x00000000
        
        # Status flags
        self.enabled = True
        self.stable = True
        self.badwrite = False
        
        # Startup delay (default ~1ms at 12MHz)
        self.startup = 0x00000000
        
        # Dormant magic value
        self.dormant = 0x00000000
        
        # Down counter
        self.count = 0x00000000
    
    def _get_status(self) -> int:
        """Calculate STATUS register value."""
        status = 0
        
        if self.stable:
            status |= self.STATUS_STABLE
        
        if self.badwrite:
            status |= self.STATUS_BADWRITE
        
        if self.enabled:
            status |= self.STATUS_ENABLED
        
        return status
    
    def read(self, offset: int, size: int) -> int:
        """Handle reads from XOSC registers."""
        
        if offset == self.CTRL:
            return self.ctrl
        
        elif offset == self.STATUS:
            return self._get_status()
        
        elif offset == self.DORMANT:
            return self.dormant
        
        elif offset == self.STARTUP:
            return self.startup
        
        elif offset == self.COUNT:
            return self.count
        
        else:
            return super().read(offset, size)
    
    def write(self, offset: int, size: int, value: int) -> None:
        """Handle writes to XOSC registers."""
        
        if offset == self.CTRL:
            self.ctrl = value
            # Check enable field (bits 23:12)
            enable_field = (value >> 12) & 0xFFF
            if enable_field == self.CTRL_ENABLE_ENABLE:
                self.enabled = True
                # In emulation, oscillator becomes stable immediately
                self.stable = True
            elif enable_field == self.CTRL_ENABLE_DISABLE:
                self.enabled = False
                self.stable = False
        
        elif offset == self.STATUS:
            # Writing 1 to BADWRITE clears it (write-1-to-clear)
            if value & self.STATUS_BADWRITE:
                self.badwrite = False
        
        elif offset == self.DORMANT:
            self.dormant = value
            # DORMANT magic values: 0x636f6d61 ('coma') or 0x77616b65 ('wake')
        
        elif offset == self.STARTUP:
            self.startup = value & 0x3FFF  # 14-bit field
        
        elif offset == self.COUNT:
            self.count = value & 0xFF  # 8-bit counter
        
        else:
            super().write(offset, size, value)
