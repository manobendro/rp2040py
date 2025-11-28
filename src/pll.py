"""
RP2040 PLL_SYS (System PLL) peripheral emulation.

The PLL_SYS peripheral controls the system phase-locked loop.
Base address: 0x40028000
"""
from peripheral import Peripheral


class PLL(Peripheral):
    """
    PLL (Phase-Locked Loop) peripheral.
    
    Base address: 0x40028000 (PLL_SYS) or 0x4002C000 (PLL_USB)
    
    Controls the PLL for generating stable high-frequency clocks.
    """
    
    # Register offsets
    CS = 0x0              # Control and Status
    PWR = 0x4             # Power control
    FBDIV_INT = 0x8       # Feedback divisor
    PRIM = 0xC            # Primary output post dividers
    
    # Size of PLL region
    PLL_SIZE = 0x10
    
    # CS register bits
    CS_LOCK = (1 << 31)        # PLL is locked
    CS_BYPASS = (1 << 8)       # Bypass PLL
    CS_REFDIV_MASK = 0x3F      # Reference clock divider (bits 5:0)
    
    # PWR register bits
    PWR_VCOPD = (1 << 5)       # VCO power down
    PWR_POSTDIVPD = (1 << 3)   # Post divider power down
    PWR_DSMPD = (1 << 2)       # DSM power down
    PWR_PD = (1 << 0)          # PLL power down
    
    def __init__(self, name: str = "PLL_SYS", base_address: int = 0x40028000):
        """
        Initialize PLL peripheral.
        
        Args:
            name: Peripheral name (PLL_SYS or PLL_USB)
            base_address: Base address (default 0x40028000 for PLL_SYS)
        """
        super().__init__(name, base_address, self.PLL_SIZE)
        
        # Control and Status - starts unlocked
        self.cs = 0x00000001  # REFDIV = 1
        
        # Power control - starts powered down
        self.pwr = self.PWR_VCOPD | self.PWR_POSTDIVPD | self.PWR_DSMPD | self.PWR_PD
        
        # Feedback divisor
        self.fbdiv_int = 0x00000000
        
        # Primary post dividers
        self.prim = 0x00077000  # Default dividers
    
    def _is_locked(self) -> bool:
        """
        Check if PLL should report as locked.
        PLL is locked when powered on and has valid feedback divisor.
        """
        # Check if powered on (all power down bits clear)
        powered_on = (self.pwr & (self.PWR_VCOPD | self.PWR_PD)) == 0
        
        # Check if feedback divisor is valid (non-zero)
        valid_fbdiv = self.fbdiv_int > 0
        
        # For emulation, lock immediately when conditions are met
        return powered_on and valid_fbdiv
    
    def _get_cs(self) -> int:
        """Get CS register value with computed LOCK bit."""
        cs = self.cs & ~self.CS_LOCK  # Clear lock bit
        if self._is_locked():
            cs |= self.CS_LOCK  # Set lock bit if locked
        return cs
    
    def read(self, offset: int, size: int) -> int:
        """Handle reads from PLL registers."""
        
        if offset == self.CS:
            return self._get_cs()
        
        elif offset == self.PWR:
            return self.pwr
        
        elif offset == self.FBDIV_INT:
            return self.fbdiv_int
        
        elif offset == self.PRIM:
            return self.prim
        
        else:
            return super().read(offset, size)
    
    def write(self, offset: int, size: int, value: int) -> None:
        """Handle writes to PLL registers."""
        
        if offset == self.CS:
            # LOCK bit is read-only, preserve it
            self.cs = value & ~self.CS_LOCK
        
        elif offset == self.PWR:
            self.pwr = value & 0x2D  # Valid bits mask
        
        elif offset == self.FBDIV_INT:
            self.fbdiv_int = value & 0xFFF  # 12-bit value
        
        elif offset == self.PRIM:
            self.prim = value & 0x00077000  # Valid bits for post dividers
        
        else:
            super().write(offset, size, value)
