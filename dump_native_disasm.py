import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

BIN = r""
OUT = r""

TARGETS = [
    ("launch_build", 0x1405a2060, 0x1405a3b7b),
    ("launch_worker_nexon_arc", 0x14058e6a0, 0x14058fb0e),
    ("manifest_signatures_files", 0x140592330, 0x1405970d0),
    ("download_build", 0x1403a8f40, 0x1403af4bf),
    ("extraction_install", 0x1403b8fd0, 0x1403bc7e3),
    ("updater", 0x1403c5610, 0x1403c6acd),
    ("websocket_loop", 0x1403beee0, 0x1403c2243),
    ("detect_fortnite_version", 0x1404b2480, 0x1404b528b),
    ("archive_tool_detection", 0x14000ec30, 0x14000f905),
    ("command_dispatch", 0x14010ed30, 0x140112f3f),
]

pe = pefile.PE(BIN, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
img = pe.get_memory_mapped_image()
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

printable = set(range(0x20, 0x7f)) | {9}

def read_string(va, maxlen=140):
    off = va - base
    if off < 0 or off >= len(img):
        return None
    raw = img[off:off+maxlen]
    end = 0
    while end < len(raw) and raw[end] in printable:
        end += 1
    if end < 3:
        return None
    return raw[:end].decode("ascii", "replace")

lines = []
for name, start, end in TARGETS:
    code = img[start-base:end-base]
    lines.append("")
    lines.append("=" * 100)
    lines.append(f"{name}  VA={start:#x}..{end:#x}  size={end-start}")
    lines.append("=" * 100)
    count = 0
    for ins in md.disasm(code, start):
        count += 1
        extra = ""
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                target = ins.address + ins.size + op.mem.disp
                s = read_string(target)
                if s:
                    extra += "  ; " + s
        lines.append(f"{ins.address:016x}  {ins.mnemonic:<8} {ins.op_str}{extra}")
    lines.append(f"; instructions: {count}")

with open(OUT, "w", encoding="utf-8", newline="\n") as f:
    f.write("\n".join(lines))
print(OUT)
print("bytes", len("\n".join(lines).encode("utf-8")))
