from base64 import b64encode
from typing import List

def base64_offsets(val : str) -> List[str]:
    # https://github.com/SigmaHQ/pySigma/blob/18c68e45fd1f38071bc877c43a6d1dd2c059f379/sigma/modifiers.py#L198
    start_offsets = (0, 2, 3)
    end_offsets = (None, -3, -2)

    return [
        b64encode(i * b" " + val.encode())[start_offsets[i] : end_offsets[(len(val) + i) % 3]].decode()
            for i in range(3)
    ]

