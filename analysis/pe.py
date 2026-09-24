import pefile

def analyze_pe(path):
    try:
        pe = pefile.PE(path)

        return {
            "architecture": hex(pe.FILE_HEADER.Machine),
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

    except (FileNotFoundError, PermissionError, OSError, pefile.PEFormatError):
        return None