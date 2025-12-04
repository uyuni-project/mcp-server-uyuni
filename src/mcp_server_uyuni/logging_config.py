import sys
import logging
from typing import Union
from .constants import Transport

def get_logger(
    name: str = "mcp_server_uyuni",
    log_level: int = logging.INFO,
    log_file: str = None,
    transport: Union[str, Transport] = None
) -> logging.Logger:

    if isinstance(transport, Transport):
        transport = transport.value

    logger = logging.getLogger(name)
    logger.setLevel(log_level)

    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
 
    handler = None
    if log_file:
        try:
            handler = logging.FileHandler(log_file)
        except Exception as e:
            print(f"Error setting up file logger at {log_file}: {e}", file=sys.stderr)
            handler = logging.StreamHandler(sys.stderr)
    else:
        if transport == Transport.HTTP.value:
            handler = logging.StreamHandler(sys.stdout)
        elif  transport == Transport.STDIO.value:
            handler = logging.StreamHandler(sys.stderr)
        else:
            # As the default transport is stdio.
            handler = logging.StreamHandler(sys.stderr)

    handler.setLevel(log_level)
    handler.setFormatter(formatter)
                         
    logger.addHandler(handler)

    return logger
