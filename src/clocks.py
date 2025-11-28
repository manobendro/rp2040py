"""
RP2040 CLOCKS peripheral emulation.

The CLOCKS peripheral controls clock generation and distribution.
Base address: 0x40008000
"""
from peripheral import Peripheral


class Clocks(Peripheral):
    """
    CLOCKS peripheral.
    
    Base address: 0x40008000
    
    Controls clock generation for the system, peripherals, and GPIO outputs.
    """
    
    # Register offsets
    CLK_GPOUT0_CTRL = 0x00
    CLK_GPOUT0_DIV = 0x04
    CLK_GPOUT0_SELECTED = 0x08
    CLK_GPOUT1_CTRL = 0x0C
    CLK_GPOUT1_DIV = 0x10
    CLK_GPOUT1_SELECTED = 0x14
    CLK_GPOUT2_CTRL = 0x18
    CLK_GPOUT2_DIV = 0x1C
    CLK_GPOUT2_SELECTED = 0x20
    CLK_GPOUT3_CTRL = 0x24
    CLK_GPOUT3_DIV = 0x28
    CLK_GPOUT3_SELECTED = 0x2C
    CLK_REF_CTRL = 0x30
    CLK_REF_DIV = 0x34
    CLK_REF_SELECTED = 0x38
    CLK_SYS_CTRL = 0x3C
    CLK_SYS_DIV = 0x40
    CLK_SYS_SELECTED = 0x44
    CLK_PERI_CTRL = 0x48
    # Note: No CLK_PERI_DIV at 0x4C
    CLK_PERI_SELECTED = 0x50
    CLK_USB_CTRL = 0x54
    CLK_USB_DIV = 0x58
    CLK_USB_SELECTED = 0x5C
    CLK_ADC_CTRL = 0x60
    CLK_ADC_DIV = 0x64
    CLK_ADC_SELECTED = 0x68
    CLK_RTC_CTRL = 0x6C
    CLK_RTC_DIV = 0x70
    CLK_RTC_SELECTED = 0x74
    CLK_SYS_RESUS_CTRL = 0x78
    CLK_SYS_RESUS_STATUS = 0x7C
    FC0_REF_KHZ = 0x80
    FC0_MIN_KHZ = 0x84
    FC0_MAX_KHZ = 0x88
    FC0_DELAY = 0x8C
    FC0_INTERVAL = 0x90
    FC0_SRC = 0x94
    FC0_STATUS = 0x98
    FC0_RESULT = 0x9C
    WAKE_EN0 = 0xA0
    WAKE_EN1 = 0xA4
    SLEEP_EN0 = 0xA8
    SLEEP_EN1 = 0xAC
    ENABLED0 = 0xB0
    ENABLED1 = 0xB4
    INTR = 0xB8
    INTE = 0xBC
    INTF = 0xC0
    INTS = 0xC4
    
    # Size of CLOCKS region
    CLOCKS_SIZE = 0xC8
    
    def __init__(self, base_address: int = 0x40008000):
        """
        Initialize CLOCKS peripheral.
        
        Args:
            base_address: Base address (default 0x40008000)
        """
        super().__init__("CLOCKS", base_address, self.CLOCKS_SIZE)
        
        # Clock control registers
        self.clk_gpout0_ctrl = 0x00000000
        self.clk_gpout0_div = 0x00000100  # Default divisor = 1.0 (8.8 fixed point)
        self.clk_gpout1_ctrl = 0x00000000
        self.clk_gpout1_div = 0x00000100
        self.clk_gpout2_ctrl = 0x00000000
        self.clk_gpout2_div = 0x00000100
        self.clk_gpout3_ctrl = 0x00000000
        self.clk_gpout3_div = 0x00000100
        
        self.clk_ref_ctrl = 0x00000000
        self.clk_ref_div = 0x00000100
        
        self.clk_sys_ctrl = 0x00000000
        self.clk_sys_div = 0x00000100
        
        self.clk_peri_ctrl = 0x00000000
        
        self.clk_usb_ctrl = 0x00000000
        self.clk_usb_div = 0x00000100
        
        self.clk_adc_ctrl = 0x00000000
        self.clk_adc_div = 0x00000100
        
        self.clk_rtc_ctrl = 0x00000000
        self.clk_rtc_div = 0x00000100
        
        # Resuscitate control/status
        self.clk_sys_resus_ctrl = 0x000000FF  # Default timeout
        self.clk_sys_resus_status = 0x00000000
        
        # Frequency counter registers
        self.fc0_ref_khz = 0x00000000
        self.fc0_min_khz = 0x00000000
        self.fc0_max_khz = 0x01FFFFFF
        self.fc0_delay = 0x00000001
        self.fc0_interval = 0x00000008  # Default interval
        self.fc0_src = 0x00000000
        self.fc0_status = 0x00000000
        self.fc0_result = 0x00000000
        
        # Wake/sleep enable
        self.wake_en0 = 0xFFFFFFFF
        self.wake_en1 = 0x00007FFF
        self.sleep_en0 = 0xFFFFFFFF
        self.sleep_en1 = 0x00007FFF
        
        # Interrupt registers
        self.inte = 0x00000000
        self.intf = 0x00000000
    
    def _get_selected(self, ctrl_value: int) -> int:
        """
        Get the SELECTED value based on CTRL register.
        Returns one-hot encoding of the selected source.
        For simplicity, always return 0x1 (first source selected).
        """
        return 0x1
    
    def _get_enabled0(self) -> int:
        """Calculate ENABLED0 based on wake enables and clock state."""
        return self.wake_en0
    
    def _get_enabled1(self) -> int:
        """Calculate ENABLED1 based on wake enables and clock state."""
        return self.wake_en1
    
    def _get_intr(self) -> int:
        """Get raw interrupt status."""
        return 0x00000000  # No interrupts pending
    
    def _get_ints(self) -> int:
        """Get masked interrupt status."""
        return (self._get_intr() & self.inte) | self.intf
    
    def read(self, offset: int, size: int) -> int:
        """Handle reads from CLOCKS registers."""
        
        # GPOUT0
        if offset == self.CLK_GPOUT0_CTRL:
            return self.clk_gpout0_ctrl & 0b100110001110111100000
        elif offset == self.CLK_GPOUT0_DIV:
            return self.clk_gpout0_div
        elif offset == self.CLK_GPOUT0_SELECTED:
            return self._get_selected(self.clk_gpout0_ctrl)
        
        # GPOUT1
        elif offset == self.CLK_GPOUT1_CTRL:
            return self.clk_gpout1_ctrl & 0b100110001110111100000
        elif offset == self.CLK_GPOUT1_DIV:
            return self.clk_gpout1_div
        elif offset == self.CLK_GPOUT1_SELECTED:
            return self._get_selected(self.clk_gpout1_ctrl)
        
        # GPOUT2
        elif offset == self.CLK_GPOUT2_CTRL:
            return self.clk_gpout2_ctrl & 0b100110001110111100000
        elif offset == self.CLK_GPOUT2_DIV:
            return self.clk_gpout2_div
        elif offset == self.CLK_GPOUT2_SELECTED:
            return self._get_selected(self.clk_gpout2_ctrl)
        
        # GPOUT3
        elif offset == self.CLK_GPOUT3_CTRL:
            return self.clk_gpout3_ctrl & 0b100110001110111100000
        elif offset == self.CLK_GPOUT3_DIV:
            return self.clk_gpout3_div
        elif offset == self.CLK_GPOUT3_SELECTED:
            return self._get_selected(self.clk_gpout3_ctrl)
        
        # REF
        elif offset == self.CLK_REF_CTRL:
            return self.clk_ref_ctrl & 0b000001100011
        elif offset == self.CLK_REF_DIV:
            return self.clk_ref_div & 0x30
        elif offset == self.CLK_REF_SELECTED:
            return 1 << (self.clk_ref_ctrl & 0x30)
        
        # SYS
        elif offset == self.CLK_SYS_CTRL:
            return self.clk_sys_ctrl & 0b000011100001
        elif offset == self.CLK_SYS_DIV:
            return self.clk_sys_div
        elif offset == self.CLK_SYS_SELECTED:
            return 1 << (self.clk_sys_ctrl & 0x01)
        
        # PERI
        elif offset == self.CLK_PERI_CTRL:
            return self.clk_peri_ctrl & 0b110011100000
        elif offset == self.CLK_PERI_SELECTED:
            return self._get_selected(self.clk_peri_ctrl)
        
        # USB
        elif offset == self.CLK_USB_CTRL:
            return self.clk_usb_ctrl & 0b100110000110011100000
        elif offset == self.CLK_USB_DIV:
            return self.clk_usb_div
        elif offset == self.CLK_USB_SELECTED:
            return self._get_selected(self.clk_usb_ctrl)
        
        # ADC
        elif offset == self.CLK_ADC_CTRL:
            return self.clk_adc_ctrl & 0b100110000110011100000
        elif offset == self.CLK_ADC_DIV:
            return self.clk_adc_div & 0x30
        elif offset == self.CLK_ADC_SELECTED:
            return self._get_selected(self.clk_adc_ctrl)
        
        # RTC
        elif offset == self.CLK_RTC_CTRL:
            return self.clk_rtc_ctrl & 0b100110000110011100000
        elif offset == self.CLK_RTC_DIV:
            return self.clk_rtc_div & 0x30
        elif offset == self.CLK_RTC_SELECTED:
            return self._get_selected(self.clk_rtc_ctrl)
        
        # RESUS
        elif offset == self.CLK_SYS_RESUS_CTRL:
            return 0xff
        elif offset == self.CLK_SYS_RESUS_STATUS:
            return 0x00
        
        # Frequency counter
        elif offset == self.FC0_REF_KHZ:
            return self.fc0_ref_khz
        elif offset == self.FC0_MIN_KHZ:
            return self.fc0_min_khz
        elif offset == self.FC0_MAX_KHZ:
            return self.fc0_max_khz
        elif offset == self.FC0_DELAY:
            return self.fc0_delay
        elif offset == self.FC0_INTERVAL:
            return self.fc0_interval
        elif offset == self.FC0_SRC:
            return self.fc0_src
        elif offset == self.FC0_STATUS:
            return self.fc0_status
        elif offset == self.FC0_RESULT:
            return self.fc0_result
        
        # Wake/sleep enables
        elif offset == self.WAKE_EN0:
            return self.wake_en0
        elif offset == self.WAKE_EN1:
            return self.wake_en1
        elif offset == self.SLEEP_EN0:
            return self.sleep_en0
        elif offset == self.SLEEP_EN1:
            return self.sleep_en1
        
        # Enabled status (read-only)
        elif offset == self.ENABLED0:
            return self._get_enabled0()
        elif offset == self.ENABLED1:
            return self._get_enabled1()
        
        # Interrupts
        elif offset == self.INTR:
            return self._get_intr()
        elif offset == self.INTE:
            return self.inte
        elif offset == self.INTF:
            return self.intf
        elif offset == self.INTS:
            return self._get_ints()
        
        else:
            return super().read(offset, size)
    
    def write(self, offset: int, size: int, value: int) -> None:
        """Handle writes to CLOCKS registers."""
        
        # GPOUT0
        if offset == self.CLK_GPOUT0_CTRL:
            self.clk_gpout0_ctrl = value
        elif offset == self.CLK_GPOUT0_DIV:
            self.clk_gpout0_div = value
        elif offset == self.CLK_GPOUT0_SELECTED:
            pass  # Read-only
        
        # GPOUT1
        elif offset == self.CLK_GPOUT1_CTRL:
            self.clk_gpout1_ctrl = value
        elif offset == self.CLK_GPOUT1_DIV:
            self.clk_gpout1_div = value
        elif offset == self.CLK_GPOUT1_SELECTED:
            pass  # Read-only
        
        # GPOUT2
        elif offset == self.CLK_GPOUT2_CTRL:
            self.clk_gpout2_ctrl = value
        elif offset == self.CLK_GPOUT2_DIV:
            self.clk_gpout2_div = value
        elif offset == self.CLK_GPOUT2_SELECTED:
            pass  # Read-only
        
        # GPOUT3
        elif offset == self.CLK_GPOUT3_CTRL:
            self.clk_gpout3_ctrl = value
        elif offset == self.CLK_GPOUT3_DIV:
            self.clk_gpout3_div = value
        elif offset == self.CLK_GPOUT3_SELECTED:
            pass  # Read-only
        
        # REF
        elif offset == self.CLK_REF_CTRL:
            self.clk_ref_ctrl = value
        elif offset == self.CLK_REF_DIV:
            self.clk_ref_div = value
        elif offset == self.CLK_REF_SELECTED:
            pass  # Read-only
        
        # SYS
        elif offset == self.CLK_SYS_CTRL:
            self.clk_sys_ctrl = value
        elif offset == self.CLK_SYS_DIV:
            self.clk_sys_div = value
        elif offset == self.CLK_SYS_SELECTED:
            pass  # Read-only
        
        # PERI
        elif offset == self.CLK_PERI_CTRL:
            self.clk_peri_ctrl = value
        elif offset == self.CLK_PERI_SELECTED:
            pass  # Read-only
        
        # USB
        elif offset == self.CLK_USB_CTRL:
            self.clk_usb_ctrl = value
        elif offset == self.CLK_USB_DIV:
            self.clk_usb_div = value
        elif offset == self.CLK_USB_SELECTED:
            pass  # Read-only
        
        # ADC
        elif offset == self.CLK_ADC_CTRL:
            self.clk_adc_ctrl = value
        elif offset == self.CLK_ADC_DIV:
            self.clk_adc_div = value
        elif offset == self.CLK_ADC_SELECTED:
            pass  # Read-only
        
        # RTC
        elif offset == self.CLK_RTC_CTRL:
            self.clk_rtc_ctrl = value
        elif offset == self.CLK_RTC_DIV:
            self.clk_rtc_div = value
        elif offset == self.CLK_RTC_SELECTED:
            pass  # Read-only
        
        # RESUS
        elif offset == self.CLK_SYS_RESUS_CTRL:
            self.clk_sys_resus_ctrl = value
        elif offset == self.CLK_SYS_RESUS_STATUS:
            pass  # Read-only
        
        # Frequency counter
        elif offset == self.FC0_REF_KHZ:
            self.fc0_ref_khz = value
        elif offset == self.FC0_MIN_KHZ:
            self.fc0_min_khz = value
        elif offset == self.FC0_MAX_KHZ:
            self.fc0_max_khz = value
        elif offset == self.FC0_DELAY:
            self.fc0_delay = value
        elif offset == self.FC0_INTERVAL:
            self.fc0_interval = value
        elif offset == self.FC0_SRC:
            self.fc0_src = value
            # Writing to FC0_SRC initiates frequency count
            # For emulation, just mark as done immediately
            self.fc0_status = 0x00000010  # DONE bit set
        elif offset == self.FC0_STATUS:
            pass  # Read-only
        elif offset == self.FC0_RESULT:
            pass  # Read-only
        
        # Wake/sleep enables
        elif offset == self.WAKE_EN0:
            self.wake_en0 = value
        elif offset == self.WAKE_EN1:
            self.wake_en1 = value
        elif offset == self.SLEEP_EN0:
            self.sleep_en0 = value
        elif offset == self.SLEEP_EN1:
            self.sleep_en1 = value
        
        # Enabled status (read-only)
        elif offset == self.ENABLED0:
            pass
        elif offset == self.ENABLED1:
            pass
        
        # Interrupts
        elif offset == self.INTR:
            pass  # Read-only / write-to-clear
        elif offset == self.INTE:
            self.inte = value
        elif offset == self.INTF:
            self.intf = value
        elif offset == self.INTS:
            pass  # Read-only
        
        else:
            super().write(offset, size, value)
