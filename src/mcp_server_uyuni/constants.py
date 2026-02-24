from enum import Enum
from typing import Literal

class Transport(Enum):
    STDIO = "stdio"
    HTTP = "http"


AdvisoryType = Literal[
    "Security Advisory",
    "Product Enhancement Advisory",
    "Bug Fix Advisory",
]
