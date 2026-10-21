import csv
import re
import sys
from collections import defaultdict

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

BIN = r""
STRINGS = r""
OUT = r""

pe = pefile.PE(BIN, fast_load=True)
image_base = pe.OPTIONAL_HEADER.ImageBase
image = pe.get_memory_mapped_image()

# Load app-specific strings from the earlier ASCII extraction. Keep only plausible
# literals from the application string region and a few semantic keywords.
phrases = []
seen = set()
keywords = (
    "Fortnite", "Arc", "Nexon", "Rewind", "launcher", "download", "Download",
    "manifest", "signature", "socket", "clan", "Clan", "voice", "Voice",
    "poll", "Poll", "mares", "Mares", "token", "Token", "update", "Update",
    "launch", "Launch", "build", "Build", "AUTH_", "game-files-ready",
    "shop", "Shop", "friend", "Friend", "conversation", "message", "Message",
    "discord", "Discord", "hotfix", "banned", "trailer", "username",
)
for line in open(STRINGS, "r", encoding="utf-8", errors="ignore"):
    s = line.strip()
    if len(s) < 8 or len(s) > 400:
        continue
    if not any(k in s for k in keywords):
        continue
    if s in seen:
        continue
    seen.add(s)
    b = s.encode("utf-8", "ignore")
    start = 0
    while True:
        pos = image.find(b, start)
        if pos < 0:
            break
        phrases.append((image_base + pos, s, len(b)))
        start = pos + 1

# Keep exact addresses and ranges. A reference normally points at the first byte.
by_addr = {}
for addr, s, n in phrases:
    by_addr.setdefault(addr, s)
ranges = sorted((addr, addr + n, s) for addr, s, n in phrases)

# Parse .pdata RUNTIME_FUNCTION entries.
text = None
pdata = None
for sec in pe.sections:
    name = sec.Name.rstrip(b"\x00").decode("ascii", "ignore")
    if name == ".text":
        text = sec
    elif name == ".pdata":
        pdata = sec
if text is None or pdata is None:
    raise SystemExit("missing .text or .pdata")

text_va = image_base + text.VirtualAddress
text_end = text_va + max(text.Misc_VirtualSize, text.SizeOfRawData)
raw = pe.get_data(pdata.VirtualAddress, pdata.SizeOfRawData)
funcs = set()
for off in range(0, len(raw) - 11, 12):
    begin, end, unwind = (int.from_bytes(raw[off+i:off+i+4], "little") for i in (0, 4, 8))
    if begin == 0 or end <= begin:
        continue
    va = image_base + begin
    ve = image_base + end
    if va < text_va or ve > text_end or ve - va > 2_000_000:
        continue
    funcs.add((va, ve))
funcs = sorted(funcs)

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
md.skipdata = True

hits = defaultdict(list)
refs = 0
for idx, (va, ve) in enumerate(funcs):
    code = pe.get_data(va - image_base, ve - va)
    try:
        for insn in md.disasm(code, va):
            for op in insn.operands:
                if op.type != X86_OP_MEM or op.mem.base != X86_REG_RIP:
                    continue
                target = insn.address + insn.size + op.mem.disp
                if target in by_addr:
                    hits[(va, ve)].append(by_addr[target])
                    refs += 1
    except Exception:
        pass

rows = []
for (va, ve), strings in hits.items():
    uniq = []
    for s in strings:
        if s not in uniq:
            uniq.append(s)
    rows.append((len(uniq), va, ve, " | ".join(uniq)))
rows.sort(key=lambda r: (-r[0], r[1]))

with open(OUT, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f, delimiter="\t")
    w.writerow(["unique_strings", "function_va", "function_end", "strings"])
    for row in rows:
        w.writerow([row[0], hex(row[1]), hex(row[2]), row[3]])

print(f"phrases={len(phrases)} funcs={len(funcs)} matched_funcs={len(rows)} refs={refs}")
print(OUT)
for row in rows[:30]:
    print(row[0], hex(row[1]), row[3][:220])
