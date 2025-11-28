"""
RP2040 SSI (Synchronous Serial Interface) peripheral emulation.

The SSI peripheral is used for XIP (Execute-in-Place) flash access.
Base address: 0x18000000
"""
from peripheral import Peripheral


class SSI(Peripheral):
    """
    SSI (Synchronous Serial Interface) peripheral.
    
    Base address: 0x18000000
    
    Controls the QSPI interface for flash memory access.
    """
    
    # Register offsets
    CTRLR0 = 0x00          # Control register 0
    CTRLR1 = 0x04          # Master Control register 1
    SSIENR = 0x08          # SSI Enable
    MWCR = 0x0C            # Microwire Control
    SER = 0x10             # Slave enable
    BAUDR = 0x14           # Baud rate
    TXFTLR = 0x18          # TX FIFO threshold level
    RXFTLR = 0x1C          # RX FIFO threshold level
    TXFLR = 0x20           # TX FIFO level
    RXFLR = 0x24           # RX FIFO level
    SR = 0x28              # Status register
    IMR = 0x2C             # Interrupt mask
    ISR = 0x30             # Interrupt status
    RISR = 0x34            # Raw interrupt status
    TXOICR = 0x38          # TX FIFO overflow interrupt clear
    RXOICR = 0x3C          # RX FIFO overflow interrupt clear
    RXUICR = 0x40          # RX FIFO underflow interrupt clear
    MSTICR = 0x44          # Multi-master interrupt clear
    ICR = 0x48             # Interrupt clear
    DMACR = 0x4C           # DMA control
    DMATDLR = 0x50         # DMA TX data level
    DMARDLR = 0x54         # DMA RX data level
    IDR = 0x58             # Identification register
    SSI_VERSION_ID = 0x5C  # Version ID
    DR0 = 0x60             # Data Register 0 (of 36)
    RX_SAMPLE_DLY = 0xF0   # RX sample delay
    SPI_CTRLR0 = 0xF4      # SPI control
    TXD_DRIVE_EDGE = 0xF8  # TX drive edge
    
    # Size of SSI region
    SSI_SIZE = 0x100
    
    # SR (Status Register) bits
    SR_DCOL = (1 << 6)     # Data collision error
    SR_TXE = (1 << 5)      # Transmission error
    SR_RFF = (1 << 4)      # Receive FIFO full
    SR_RFNE = (1 << 3)     # Receive FIFO not empty
    SR_TFE = (1 << 2)      # Transmit FIFO empty
    SR_TFNF = (1 << 1)     # Transmit FIFO not full
    SR_BUSY = (1 << 0)     # SSI busy flag
    
    def __init__(self, base_address: int = 0x18000000):
        """
        Initialize SSI peripheral.
        
        Args:
            base_address: Base address (default 0x18000000)
        """
        super().__init__("SSI", base_address, self.SSI_SIZE)
        
        # Control registers
        self.ctrlr0 = 0x00000000
        self.ctrlr1 = 0x00000000
        self.ssienr = 0x00000000  # Disabled by default
        self.mwcr = 0x00000000
        self.ser = 0x00000000
        self.baudr = 0x00000000
        self.txftlr = 0x00000000
        self.rxftlr = 0x00000000
        
        # Interrupt registers
        self.imr = 0x0000003F  # All interrupts masked
        
        # DMA registers
        self.dmacr = 0x00000000
        self.dmatdlr = 0x00000000
        self.dmardlr = 0x00000000
        
        # SPI control
        self.rx_sample_dly = 0x00000000
        self.spi_ctrlr0 = 0x00000000
        self.txd_drive_edge = 0x00000000
        
        # TX/RX FIFOs (simplified)
        self.tx_fifo = []
        self.rx_fifo = []
        self.tx_fifo_depth = 8
        self.rx_fifo_depth = 8
    
    def _get_sr(self) -> int:
        """Calculate Status Register value."""
        sr = 0
        
        # TX FIFO empty
        if len(self.tx_fifo) == 0:
            sr |= self.SR_TFE
        
        # TX FIFO not full
        if len(self.tx_fifo) < self.tx_fifo_depth:
            sr |= self.SR_TFNF
        
        # RX FIFO not empty
        if len(self.rx_fifo) > 0:
            sr |= self.SR_RFNE
        
        # RX FIFO full
        if len(self.rx_fifo) >= self.rx_fifo_depth:
            sr |= self.SR_RFF
        
        # Not busy (for emulation, always idle)
        # sr |= self.SR_BUSY
        
        return sr
    
    def _get_txflr(self) -> int:
        """Get TX FIFO level."""
        return len(self.tx_fifo)
    
    def _get_rxflr(self) -> int:
        """Get RX FIFO level."""
        return len(self.rx_fifo)
    
    def read(self, offset: int, size: int) -> int:
        """Handle reads from SSI registers."""
        
        if offset == self.CTRLR0:
            return self.ctrlr0
        
        elif offset == self.CTRLR1:
            return self.ctrlr1
        
        elif offset == self.SSIENR:
            return self.ssienr
        
        elif offset == self.MWCR:
            return self.mwcr
        
        elif offset == self.SER:
            return self.ser
        
        elif offset == self.BAUDR:
            return self.baudr
        
        elif offset == self.TXFTLR:
            return self.txftlr
        
        elif offset == self.RXFTLR:
            return self.rxftlr
        
        elif offset == self.TXFLR:
            return self._get_txflr()
        
        elif offset == self.RXFLR:
            return self._get_rxflr()
        
        elif offset == self.SR:
            return self._get_sr()
        
        elif offset == self.IMR:
            return self.imr
        
        elif offset == self.ISR:
            return 0x00000000  # No interrupts pending
        
        elif offset == self.RISR:
            return 0x00000000  # No raw interrupts
        
        elif offset == self.TXOICR:
            return 0x00000000  # Reading clears interrupt
        
        elif offset == self.RXOICR:
            return 0x00000000
        
        elif offset == self.RXUICR:
            return 0x00000000
        
        elif offset == self.MSTICR:
            return 0x00000000
        
        elif offset == self.ICR:
            return 0x00000000
        
        elif offset == self.DMACR:
            return self.dmacr
        
        elif offset == self.DMATDLR:
            return self.dmatdlr
        
        elif offset == self.DMARDLR:
            return self.dmardlr
        
        elif offset == self.IDR:
            return 0x51535049  # "QSPI" identifier
        
        elif offset == self.SSI_VERSION_ID:
            return 0x3430312A  # Version string
        
        elif offset >= self.DR0 and offset < self.DR0 + 36 * 4:
            # Data register read - pop from RX FIFO
            if len(self.rx_fifo) > 0:
                return self.rx_fifo.pop(0)
            return 0x00000000
        
        elif offset == self.RX_SAMPLE_DLY:
            return self.rx_sample_dly
        
        elif offset == self.SPI_CTRLR0:
            return self.spi_ctrlr0
        
        elif offset == self.TXD_DRIVE_EDGE:
            return self.txd_drive_edge
        
        else:
            return super().read(offset, size)
    
    def write(self, offset: int, size: int, value: int) -> None:
        """Handle writes to SSI registers."""
        
        if offset == self.CTRLR0:
            self.ctrlr0 = value
        
        elif offset == self.CTRLR1:
            self.ctrlr1 = value
        
        elif offset == self.SSIENR:
            self.ssienr = value & 0x1
            if self.ssienr == 0:
                # When disabled, clear FIFOs
                self.tx_fifo.clear()
                self.rx_fifo.clear()
        
        elif offset == self.MWCR:
            self.mwcr = value
        
        elif offset == self.SER:
            self.ser = value
        
        elif offset == self.BAUDR:
            self.baudr = value
        
        elif offset == self.TXFTLR:
            self.txftlr = value
        
        elif offset == self.RXFTLR:
            self.rxftlr = value
        
        elif offset == self.TXFLR:
            pass  # Read-only
        
        elif offset == self.RXFLR:
            pass  # Read-only
        
        elif offset == self.SR:
            pass  # Read-only
        
        elif offset == self.IMR:
            self.imr = value & 0x3F
        
        elif offset == self.ISR:
            pass  # Read-only
        
        elif offset == self.RISR:
            pass  # Read-only
        
        elif offset == self.TXOICR:
            pass  # Read to clear
        
        elif offset == self.RXOICR:
            pass  # Read to clear
        
        elif offset == self.RXUICR:
            pass  # Read to clear
        
        elif offset == self.MSTICR:
            pass  # Read to clear
        
        elif offset == self.ICR:
            pass  # Read to clear
        
        elif offset == self.DMACR:
            self.dmacr = value & 0x3
        
        elif offset == self.DMATDLR:
            self.dmatdlr = value
        
        elif offset == self.DMARDLR:
            self.dmardlr = value
        
        elif offset == self.IDR:
            pass  # Read-only
        
        elif offset == self.SSI_VERSION_ID:
            pass  # Read-only
        
        elif offset >= self.DR0 and offset < self.DR0 + 36 * 4:
            # Data register write - push to TX FIFO
            if len(self.tx_fifo) < self.tx_fifo_depth:
                self.tx_fifo.append(value)
                # For emulation, immediately "transfer" to RX FIFO
                # This simulates a loopback or immediate response
                if len(self.rx_fifo) < self.rx_fifo_depth:
                    self.rx_fifo.append(0xFF)  # Dummy response
        
        elif offset == self.RX_SAMPLE_DLY:
            self.rx_sample_dly = value & 0xFF
        
        elif offset == self.SPI_CTRLR0:
            self.spi_ctrlr0 = value
        
        elif offset == self.TXD_DRIVE_EDGE:
            self.txd_drive_edge = value & 0xFF
        
        else:
            super().write(offset, size, value)
