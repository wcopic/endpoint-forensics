import pefile


def analyze_pe(path):
    pe = None

    try:
        pe = pefile.PE(
            path,
            fast_load=True
        )

        return {
            "architecture": hex(
                pe.FILE_HEADER.Machine
            ),
            "subsystem": pefile.SUBSYSTEM_TYPE.get(
                pe.OPTIONAL_HEADER.Subsystem,
                "Unknown"
            ),
            "entry_point": hex(
                pe.OPTIONAL_HEADER.AddressOfEntryPoint
            ),
            "image_base": hex(
                pe.OPTIONAL_HEADER.ImageBase
            ),
        }

    except (
        FileNotFoundError,
        PermissionError,
        OSError,
        pefile.PEFormatError
    ):
        return None

    finally:
        if pe is not None:
            pe.close()