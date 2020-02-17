from enum import Enum


class ERROR(Enum):
    DOWNLOAD_ERROR = -1
    CORRUPT_ZIP = -2
    EMPTY_ZIP = -3
