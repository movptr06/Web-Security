import sys
import os

PATH = "../../src"

sys.path.insert(
    0,
    os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            PATH
        )
    )
)
