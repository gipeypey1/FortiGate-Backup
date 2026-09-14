"""Device handler modules for FortiGate and FortiWeb."""
from .base import BaseFortinetDevice, DeviceError, TruncatedBackupError
from .fortigate import FortiGateDevice
from .fortiweb import FortiWebDevice

__all__ = [
    "BaseFortinetDevice",
    "DeviceError",
    "TruncatedBackupError",
    "FortiGateDevice",
    "FortiWebDevice"
]

