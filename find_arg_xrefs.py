import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP
BIN=r""
pe=pefile.PE(BIN, fast_load=True); base=pe.OPTIONAL_HEADER.ImageBase; img=pe.get_memory_mapped_image()
text=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text'); pdata=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.pdata')
text_va=base+text.VirtualAddress; text_end=text_va+max(text.Misc_VirtualSize,text.SizeOfRawData)
raw=pe.get_data(pdata.VirtualAddress,pdata.SizeOfRawData)
funcs=set()
for off in range(0,len(raw)-11,12):
    b,e,u=(int.from_bytes(raw[off+i:off+i+4],'little') for i in (0,4,8))
    if b and e>b:
        va=base+b; ve=base+e
        if va>=text_va and ve<=text_end and ve-va<2000000: funcs.add((va,ve))
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
keys=[b'-AUTH_LOGIN=',b'-AUTH_PASSWORD=',b'-FeatureLevelES31',b'FortniteLauncher.exe',b'-D3D11',b'-D3D12']
found={k:[] for k in keys}
for va,ve in sorted(funcs):
    code=pe.get_data(va-base,ve-va)
    try:
        for ins in md.disasm(code,va):
            for op in ins.operands:
                if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
                    t=ins.address+ins.size+op.mem.disp
                    off=t-base
                    if 0<=off<len(img):
                        chunk=img[off:off+260]
                        for k in keys:
                            if k in chunk and len(found[k])<12:
                                found[k].append((va,ve,t,chunk[:180].split(b'\0')[0].decode('ascii','replace')))
    except Exception: pass
for k,v in found.items():
    print(k.decode())
    for x in v[:6]: print(' ',hex(x[0]),hex(x[1]),hex(x[2]),repr(x[3][:160]))
