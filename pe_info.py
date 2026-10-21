import json
import hashlib
import math
import sys
from pathlib import Path

import pefile


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def decode(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").rstrip("\x00")
    return value


def resource_entries(pe):
    result = []
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return result
    for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        type_name = decode(type_entry.name) if type_entry.name else str(type_entry.id)
        for id_entry in type_entry.directory.entries:
            id_name = decode(id_entry.name) if id_entry.name else str(id_entry.id)
            for lang_entry in id_entry.directory.entries:
                data = lang_entry.data.struct
                payload = pe.get_data(data.OffsetToData, data.Size)
                result.append(
                    {
                        "type": type_name,
                        "id": id_name,
                        "language": lang_entry.id,
                        "size": data.Size,
                        "codepage": data.CodePage,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                )
    return result


def version_info(pe):
    result = {}
    if not hasattr(pe, "FileInfo"):
        return result
    for file_info in pe.FileInfo:
        for entry in file_info:
            if entry.Key == b"StringFileInfo":
                for table in entry.StringTable:
                    for key, value in table.entries.items():
                        result[decode(key)] = decode(value)
            elif entry.Key == b"VarFileInfo":
                for var in entry.Var:
                    key = getattr(var, "Key", None)
                    if key is None:
                        key = getattr(getattr(var, "entry", None), "Key", None)
                    values = getattr(getattr(var, "entry", None), "values", None)
                    if key is not None and values is not None:
                        result[decode(key)] = [decode(v) for v in values]
    return result


def manifest(pe):
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return None
    for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if type_entry.id != 24:
            continue
        for id_entry in type_entry.directory.entries:
            for lang_entry in id_entry.directory.entries:
                data = lang_entry.data.struct
                return decode(pe.get_data(data.OffsetToData, data.Size))
    return None


def main():
    path = Path(sys.argv[1])
    pe = pefile.PE(str(path), fast_load=False)
    obj = {
        "path": str(path),
        "bytes": path.stat().st_size,
        "sha256": sha256(path),
        "machine": hex(pe.FILE_HEADER.Machine),
        "machine_name": pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine),
        "number_of_sections": pe.FILE_HEADER.NumberOfSections,
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "characteristics": hex(pe.FILE_HEADER.Characteristics),
        "optional_magic": hex(pe.OPTIONAL_HEADER.Magic),
        "subsystem": pe.OPTIONAL_HEADER.Subsystem,
        "subsystem_name": pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem),
        "dll_characteristics": hex(pe.OPTIONAL_HEADER.DllCharacteristics),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "entry_point_rva": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "size_of_image": pe.OPTIONAL_HEADER.SizeOfImage,
        "size_of_headers": pe.OPTIONAL_HEADER.SizeOfHeaders,
        "checksum": hex(pe.OPTIONAL_HEADER.CheckSum),
        "sections": [],
        "imports": [],
        "exports": [],
        "resources": resource_entries(pe),
        "version_info": version_info(pe),
        "manifest": manifest(pe),
        "debug": [],
        "overlay": None,
        "signature": None,
        "rich_header": None,
    }

    for index, section in enumerate(pe.sections):
        name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        obj["sections"].append(
            {
                "index": index,
                "name": name,
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_pointer": hex(section.PointerToRawData),
                "raw_size": section.SizeOfRawData,
                "characteristics": hex(section.Characteristics),
                "entropy": round(section.get_entropy(), 4),
                "md5": section.get_hash_md5(),
                "sha256": section.get_hash_sha256(),
            }
        )

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            functions = []
            for imp in entry.imports:
                functions.append(
                    {
                        "name": decode(imp.name) if imp.name else None,
                        "ordinal": imp.ordinal,
                        "address": hex(imp.address) if imp.address else None,
                    }
                )
            obj["imports"].append(
                {"dll": decode(entry.dll), "functions": functions}
            )

    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT.symbols:
        for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            obj["exports"].append(
                {
                    "name": decode(symbol.name) if symbol.name else None,
                    "ordinal": symbol.ordinal,
                    "address": hex(symbol.address) if symbol.address else None,
                }
            )

    if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        for debug in pe.DIRECTORY_ENTRY_DEBUG:
            entry = {"type": debug.struct.Type, "size": debug.struct.SizeOfData}
            if hasattr(debug, "entry"):
                entry["pdb"] = decode(getattr(debug.entry, "PdbFileName", b""))
                entry["timestamp"] = getattr(debug.struct, "TimeDateStamp", None)
                entry["age"] = getattr(debug.entry, "Age", None)
                entry["signature"] = getattr(debug.entry, "Signature", None)
            obj["debug"].append(entry)

    overlay_start = pe.get_overlay_data_start_offset()
    if overlay_start is not None:
        obj["overlay"] = {
            "offset": overlay_start,
            "size": path.stat().st_size - overlay_start,
        }

    security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
    if security.VirtualAddress and security.Size:
        start = security.VirtualAddress
        payload = path.read_bytes()[start:start + security.Size]
        obj["signature"] = {
            "offset": start,
            "size": security.Size,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "length": int.from_bytes(payload[0:4], "little") if len(payload) >= 8 else None,
            "revision": int.from_bytes(payload[4:6], "little") if len(payload) >= 8 else None,
            "certificate_type": int.from_bytes(payload[6:8], "little") if len(payload) >= 8 else None,
        }

    try:
        rich = pe.parse_rich_header()
        if rich:
            obj["rich_header"] = {
                "checksum": hex(rich.get("checksum", 0)),
                "values": [hex(value) for value in rich.get("values", [])],
            }
    except Exception as exc:
        obj["rich_header"] = {"error": str(exc)}

    print(json.dumps(obj, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
