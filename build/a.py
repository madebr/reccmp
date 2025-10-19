#!/usr/bin/env python

import binascii
import io

import reccmp.isledecomp.formats
from reccmp.isledecomp.formats.coff import *
obj: reccmp.isledecomp.formats.COFFObject = reccmp.isledecomp.formats.detect_image('/home/maarten/programming/reccmp/build/b.msvc42.obj')



print("sections:")
for i, s in enumerate(obj.sections):
 print(f"- {i+1}: {s.header} align={s.header.characteristics.alignment}")#{s.name} (flags={s.header.characteristics.name} alignment={s.header.characteristics.alignment}) rptr={s.header.pointer_to_raw_data} rlen={s.header.size_of_raw_data}")  # vptr={s.header.virtual_address} vlen={s.header.virtual_size}
 print(f"     virtual_size={s.header.virtual_size} raw_size={s.header.size_of_raw_data}")
 print(f"     relocations={s.relocations}")
 for symi, sym in enumerate(obj.symbols.values()):
     if sym.section_number != i + 1:
        continue
     print(f"    sym {symi} {sym.name}")

print(f"symbols: (#={obj.header.number_of_symbols})")
for s in obj.symbols.values():
 print(f"- {s.index}: {s.name} (#={s.number_of_aux_symbols} val={s.value} sec={s.section_number} type={repr(s.type)}) storage_class={s.storage_class.name}")
 if s.aux is not None:
   print(f"  > {s.aux}")

if 0:
    print(f"String table (size={len(obj.string_table.raw_table)})")
    print(obj.string_table.raw_table)
    for o, s in obj.string_table.items():
        print(f"{o}: {s}")
# [(22, 0), (9, 1), (18, 2), (47, 3), (59, 4),

discarable_sections = []
keep_sections = []
for section in obj.sections:
    if section.header.characteristics & (PESectionFlags.IMAGE_SCN_MEM_DISCARDABLE | PESectionFlags.IMAGE_SCN_LNK_REMOVE):
        discarable_sections.append(section)
    else:
        keep_sections.append(section)

texts: list[COFFSection] = []
data: list[COFFSection] = []
rdata: list[COFFSection] = []
for section in keep_sections:
    if section.header.characteristics & PESectionFlags.IMAGE_SCN_MEM_EXECUTE:
        texts.append(section)
    elif section.header.characteristics & PESectionFlags.IMAGE_SCN_MEM_WRITE:
        data.append(section)
    elif section.header.characteristics & PESectionFlags.IMAGE_SCN_MEM_READ:
        rdata.append(section)
    else:
        assert False

print(f"Discardable: f{[section.name for section in discarable_sections]}")
print(f"exec:  {[section.name for section in texts]}")
print(f"rdata: {[section.name for section in rdata]}")
print(f"data:  {[section.name for section in data]}")

sort_key_lambda = lambda s: (1 if s.header.pointer_to_raw_data == 0 else 0, s.name.lower(), s.index)
texts.sort(key=sort_key_lambda)
rdata.sort(key=sort_key_lambda)
data.sort(key=sort_key_lambda)

print("AFTER SORT")
print(f"exec:  {[section.name for section in texts]}")
print(f"rdata: {[section.name for section in rdata]}")
print(f"data:  {[section.name for section in data]}")
# print([(d.name, sort_key_lambda(d), d.header.pointer_to_raw_data) for d in data])

minimum_alignment = 16
section_alignment = 4096
text_fill_byte = b'\x90'  # or '\xcc'
data_fill_byte = b'\x00'
proto_external_function = b'\xcc\xeb\xfd'  # LABEL: INT3; jmp LABEL;
proto_external_data = b'external_data\x00'

def align(v: int, alignment: int) -> int:
    return (v + alignment - 1) & ~(alignment - 1)

def align_minimum(v: int) -> int:
    return align(v, minimum_alignment)

def align_section(v: int) -> int:
    return align(v, section_alignment)


proto_external_function += (align_minimum(len(proto_external_function)) - len(proto_external_function)) * text_fill_byte
proto_external_data += (align_minimum(len(proto_external_data)) - len(proto_external_data)) * data_fill_byte

print(proto_external_function, len(proto_external_function))
print(proto_external_data, len(proto_external_data))

external_function_syms: list[COFFSymbol] = []
external_data_syms: list[COFFSymbol] = []


for sym in obj.symbols.values():
    if sym.section_number == 0:
        if sym.type == COFFMicrosoftSymbolType.IMAGE_SYM_TYPE_FUNCTION:
            external_function_syms.append(sym)
        else:
            external_data_syms.append(sym)

external_text_section_data = len(external_function_syms) * proto_external_function
external_data_section_data = len(external_data_syms) * proto_external_data

import dataclasses

@dataclasses.dataclass
class SymbolLinkInfo:
    coff_symbol: COFFSymbol | None

@dataclasses.dataclass
class SectionLinkInfo:
    raw_start: int
    raw_end: int
    coff_section: COFFSection | None = None
    raw_data: bytes | None = None

def calculate_link_infos(sections: list[COFFSection]) -> list[SectionLinkInfo]:
    link_infos = []
    pos = 0
    for section in sections:
        alignment = max(minimum_alignment, section.header.characteristics.alignment)
        pos = (pos + alignment - 1) & ~(alignment - 1)
        link_infos.append(SectionLinkInfo(raw_start=pos, raw_end=pos + section.header.size_of_raw_data, coff_section=section))
        pos += section.header.size_of_raw_data
    return link_infos


linkinfo_texts = calculate_link_infos(texts)
linkinfo_texts.append(SectionLinkInfo(
    raw_start=align_section(linkinfo_texts[-1].raw_end),
    raw_end=align_section(linkinfo_texts[-1].raw_end) + len(external_text_section_data),
    raw_data=external_text_section_data,
))
linkinfo_rdatas = calculate_link_infos(rdata)

linkinfo_datas = calculate_link_infos(data)
linkinfo_datas.append(SectionLinkInfo(
    raw_start=align_section(linkinfo_datas[-1].raw_end),
    raw_end=align_section(linkinfo_datas[-1].raw_end) + len(external_data_section_data),
    raw_data=external_data_section_data,
))

print("text size", linkinfo_texts[-1].raw_end)
if linkinfo_rdatas:
    print("rdata size", linkinfo_rdatas[-1].raw_end)
print("data size", linkinfo_datas[-1].raw_end)

text_bytes = bytearray(text_fill_byte * align_section(linkinfo_texts[-1].raw_end))
if linkinfo_rdatas:
    rdata_bytes = bytearray(data_fill_byte * align_section(linkinfo_rdatas[-1].raw_end))
data_bytes = bytearray(data_fill_byte * align_section(linkinfo_datas[-1].raw_end))

def copy_section_data(section: bytearray, link_infos: list[SectionLinkInfo]):
    for link_info in link_infos:
        if link_info.coff_section:
            data = obj.data[link_info.coff_section.header.pointer_to_raw_data:link_info.coff_section.header.pointer_to_raw_data+link_info.coff_section.header.size_of_raw_data]
        else:
            data = link_info.raw_data
        assert link_info.raw_end - link_info.raw_start >= len(data)
        section[link_info.raw_start:link_info.raw_end] = data


copy_section_data(text_bytes, linkinfo_texts)
if rdata_bytes:
    copy_section_data(rdata_bytes, linkinfo_rdatas)
copy_section_data(data_bytes, linkinfo_datas)

text_va = 0x0040_0000
rdata_va = text_va + align_section(linkinfo_texts[-1].raw_end)
data_va = rdata_va + align_section(linkinfo_rdatas[-1].raw_end)

# Relocations

for link_info in linkinfo_texts:
    if link_info.coff_section:
        for relocation in link_info.coff_section.relocations:
            print(relocation.type.name, relocation.symbol_table_index, relocation.virtual_address)



# print(data_stream.getvalue())
