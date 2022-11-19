from .loader import PEGASUS
from .arch import EAR
from .helpers import lestring_renderer

# lestring_renderer().register_type_specific()
EAR.register()
PEGASUS.register()
