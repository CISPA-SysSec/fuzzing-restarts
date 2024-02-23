__all__ = ['FuzzerInstance', 'setup_logging', 'log', 'sileo_modes', 'main']

# To use sileo in fuzzbench 
try:
    from sileo.sileo_instances import FuzzerInstance
    from sileo.sileo_utils import setup_logging, log
    import sileo.sileo_modes as sileo_modes
    from sileo.sileo_main import main
except ImportError:
    from .sileo_instances import FuzzerInstance
    from .sileo_utils import setup_logging, log
    from . import sileo_modes
    from .sileo_main import main
