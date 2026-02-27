"""
Detector package for Secure Vibe.
"""

from .base import BaseDetector, Finding, Severity
from .javascript import JavaScriptDetector

# For backward compatibility, also export the old PythonDetector and GoDetector
try:
    from .python import PythonDetector
except ImportError:
    PythonDetector = None

try:
    from .go import GoDetector
except ImportError:
    GoDetector = None

try:
    from .generic import GenericDetector
except ImportError:
    GenericDetector = None

try:
    from .rust import RustSecurityDetector
except ImportError:
    RustSecurityDetector = None

__all__ = ["BaseDetector", "Finding", "Severity", "JavaScriptDetector"]
if PythonDetector:
    __all__.append("PythonDetector")
if GoDetector:
    __all__.append("GoDetector")
if GenericDetector:
    __all__.append("GenericDetector")
if RustSecurityDetector:
    __all__.append("RustSecurityDetector")
