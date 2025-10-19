"""
Based on the following resources:
- OMF: Relocatable Object Module Format
- dmpobj from Open Watcom
"""

import binascii
import dataclasses
import datetime
import logging
from enum import IntEnum, IntFlag
from functools import cached_property
from pathlib import Path
import struct
from typing import Iterator, cast

from .exceptions import (
    InvalidVirtualAddressError,
    SectionNotFoundError,
)
from .image import Image, ImageRegion
from .mz import ImageDosHeader

logger = logging.getLogger(__name__)


class OMFRecordType(IntEnum):
    THEADR = 0x80  # Translator Header Record
    LHEADR = 0x82  # Library Module Header Record
    COMENT = 0x88  # Comment Record (Including all comment class extensions)
    MODEND = 0x8a  # Module End Record
    EXTDEF = 0x8c  # External Names Definition Record
    PUBDEF_1 = 0x90  # Public Names Definition Record
    PUBDEF_2 = 0x91  # Public Names Definition Record
    LINNUM_1 = 0x94  # Line Numbers Record
    LINNUM_2 = 0x95  # Line Numbers Record
    LNAMES = 0x96  # LList of Names Record
    SEGDEF = 0x98  # Segment Definition Record
    SEGDEF386 = 0x99  # Segment Definition Record
    GRPDEF = 0x9A  # Group Definition Record
    FIXUPP = 0x9c  # Fixup Record
    FIXUPP386 = 0x9d  # Fixup Record
    LEDATA_1 = 0xa0  # Logical Enumerated Data Record
    LEDATA_2 = 0xa1  # Logical Enumerated Data Record
    LIDATA_1 = 0xa2  # Logical Iterated Data Record
    LIDATA_2 = 0xa3  # Logical Iterated Data Record
    COMDEF = 0xB0  # Communal Names Definition Record
    BAKPAT_1 = 0xb2  # Backpatch Record
    BAKPAT_2 = 0xb3  # Backpatch Record
    LEXTDEF = 0xb4  # Local External Names Definition Record
    LPUBDEF_1 = 0xb6  # Local Public Names Definition Record
    LPUBDEF_2 = 0xb7  # Local Public Names Definition Record
    LCOMDEF = 0xb8  # Local Communal Names Definition Record
    CEXTDEF = 0xbc  # COMDAT External Names Definition Record
    COMDAT_1 = 0xc2  # Initialized Communal Data Record
    COMDAT_2 = 0xc3  # Initialized Communal Data Record
    LINSYM_1 = 0xc4  # Symbol Line Numbers Record
    LINSYM_2 = 0xc5  # Symbol Line Numbers Record
    ALIAS = 0xc6  # Alias Definition Record
    NBKPAT_1 = 0xc8  # Named Backpatch Record
    NBKPAT_2 = 0xc9  # Named Backpatch Record
    LLNAMES = 0xca  # Local Logical Names Definition Record
    VERNUM = 0xcc  # OMF Version Number Record
    VENDEXT = 0xce  # Vendor-specific OMF Extension Record
    EXT_LIBHDR = 0xf0  # Library Header Record
                       # (Although this is not actually an OMF record type, the presence of a record with
                       # 0xf0 the first byte indicates that the module is a library.)
    EXT_LIBEND = 0xf1  # Library End Record


def is_valid_record_checksum(s: bytes, start: int, end: int, checksum: int) -> bool:
    if checksum == 0:
        return True
    calculated_checksum = sum(s[i] for i in range(start, end)) % 256
    return calculated_checksum == checksum


def verify_record_checksum(s: bytes, start: int, end: int, checksum: int) -> None:
    if not is_valid_record_checksum(s, start, end, checksum):
        raise ValueError("Invalid checksum")


class WrongRecordType(Exception):
    pass


def parse_THEADR(data: bytes, offset: int, size: int):
    string_length, = struct.unpack_from("<B", data, offset)
    if string_length > size - 1:
        logging.warning("THEADR: String Length (%d) > Record Length (%s): terminating string", string_length, size)
        string_length = size - 1
    elif string_length < size - 1:
        logging.warning("THEADR: String Length (%d) < Record Length (%s): possible garbage data", string_length, size)
    name, = struct.unpack_from(f"<{string_length}s", data, offset + 1)
    # FIXME
    print("THEADR: name=", name)


class OMFCommentClassType(IntEnum):
    Translator = 0x00
    IntelCopyright = 0x01
    IntelReserved_start = 0x02
    IntelReserved_end = 0x9b
    MSDOS_Version = 0x9c
    MemoryModel = 0x9d
    DOSSEG = 0x9e
    DefaultLibrarySearchName = 0x9f
    OMFExtension = 0xa0
    NewOMFExtension = 0xa1
    LinkPassSeparator = 0xa2
    LIBMOD = 0xa3
    EXESTR = 0xa4
    INCERR = 0xa6
    NOPAD = 0xa7
    WKEXT = 0xa8
    LZEXT = 0xa9
    COMMENT = 0xda
    COMPILER = 0xdb
    DATE = 0xdc
    TIMESTAMP = 0xdd
    USER = 0xdf
    DEPENDENCY_FILE = 0xe9
    COMMAND_LINE = 0xff



def parse_COMENT(data: bytes, offset: int, size: int):
    position = offset
    comment_type, comment_cls = struct.unpack_from(f"<BB", data, position)
    position += 2
    no_purge_bit = bool(comment_type & 0x1)
    no_list_bit = bool(comment_type & 0x2)
    if comment_type & 0xfc:
        logger.warning("COMENT: Unknown bits in comment_type %02x", comment_type)
    # FIXME
    print(f"COMENT: NP={no_purge_bit} NL={no_list_bit}")
    match comment_cls:
        case OMFCommentClassType.NewOMFExtension:
            debug_version, debug_type = struct.unpack_from("<B2s", data, position)
            position += 3
            assert debug_type in (b"CV", b"DX", b"HL")
            print(f"COMENT: debug type {debug_type.decode()} version {debug_version}")
        case OMFCommentClassType.MemoryModel:
            s, = struct.unpack_from(f"<{size - (position - offset)}s", data, position)
            position = offset + size
            processor = None
            optimizations = False
            memory_model = None
            for c in s:
                c_bytes = bytes((c,))
                match c_bytes:
                    case b"0":
                        assert not processor
                        processor = "8086"
                    case b"1":
                        assert not processor
                        processor = "80186"
                    case b"2":
                        assert not processor
                        processor = "80286"
                    case b"3":
                        assert not processor
                        processor = "80386"
                    case b"O":
                        optimizations = True
                    case b"s":
                        assert not memory_model
                        memory_model = "small"
                    case b"m":
                        assert not memory_model
                        memory_model = "medium"
                    case b"c":
                        assert not memory_model
                        memory_model = "compact"
                    case b"l":
                        assert not memory_model
                        memory_model = "large"
                    case b"h":
                        assert not memory_model
                        memory_model = "huge"
                    case b"A":
                        assert not processor
                        processor = "68000"
                    case b"B":
                        assert not processor
                        processor = "68010"
                    case b"C":
                        assert not processor
                        processor = "68020"
                    case b"D":
                        assert not processor
                        processor = "68030"
                    case _:
                        raise ValueError(f"Invalid memory model: {c_bytes}")
            print(f"{processor=} {optimizations=} {memory_model}")
        case OMFCommentClassType.DefaultLibrarySearchName:
            default_library_search_name, = struct.unpack_from(f"<{size - (position - offset)}s", data, position)
            position = offset + size
            print(f"COMENT: {default_library_search_name=}")
        case _:
            raise NotImplementedError(f"COMENT class 0x{comment_cls:02x} not implemented")
    assert offset + size == position


def parse_LNAMES(data: bytes, offset: int, size: int) -> list[bytes]:
    left = size
    names = []
    while left >= 1:
        name_length, = struct.unpack_from("<B", data, offset)
        if name_length > left - 1:
            logger.warning("LNAMES: member cut off (name_length=%d left=%d)", name_length, left)
            name_length = left - 1
        if name_length > 0:
            name, = struct.unpack_from(f"<{name_length}s", data, offset + 1)
        else:
            name = b""
        names.append(name)
        left -= name_length + 1
        offset += name_length + 1
    print("LNAMES:", names)
    return names


def parse_SEGDEF(data: bytes, offset: int, size: int, use_32bit: bool, names: list[bytes]):
    position = offset
    segattr_b1, = struct.unpack_from("<B", data, position)
    position += 1
    # alignment_flag = segattr_b1 & 0x7
    # combination_flag = (segattr_b1 & 0x38) >> 3
    # big = bool(segattr_b1 & 0x40)
    # segment_size_high_bit = bool(segattr_b1 & 0x80)

    alignment_flag = (segattr_b1 & 0b1110_0000) >> 5
    combination_flag = (segattr_b1 & 0x0001_1100) >> 2
    big = bool(segattr_b1 & 0b0000_0010)  # Segment is 4 GiB
    segment_size_high_bit = bool(segattr_b1 & 0b0000_0001)  # use 16/32-bit

    relocatable = False
    segment_location = None
    segment_offset = None
    segment_alignment = -1
    if alignment_flag == 0:
        relocatable = False
        segment_location, segment_offset = struct.unpack_from("<HB", data, position)
        position += 3
    else:
        match alignment_flag:
            case 1:
                relocatable = True
                segment_alignment = 1
            case 2:
                relocatable = True
                segment_alignment = 2
            case 3:
                relocatable = True
                segment_alignment = 16
            case 4:
                assert use_32bit, "page alignment only supported for 32-bit linkers"
                segment_alignment = 4096
            case 5:
                assert use_32bit, "page alignment only supported for 32-bit linkers"
                relocatable = True
                segment_alignment = 4
            case 6: assert False, "Not supported"
            case 7: assert False, "Not defined"
    match combination_flag:
        case 0 | 4 | 7: pass  # Do not combine
        case 1: assert False  # Reserved
        case 2: pass  # Public (Combine by appending at an offset that meets the alignment requirement)
        case 3: assert False  # Reserved
        case 5: segment_alignment = 1  # Stack alignment, forces byte alignment
        case 6: pass  # overlay using maximum size
    if use_32bit:
        segment_size, = struct.unpack_from("<I", data, position)
        position += 4
    else:
        segment_size, = struct.unpack_from("<H", data, position)
        position += 2
    segment_name_index, segment_class_index, segment_overlay_name_index = struct.unpack_from("<BBB", data, position)
    position += 3
    if big:
        if segment_size != 0:
            logger.warning("SEGDEF: B=1, but segment_size is not 0")
        if use_32bit:
            segment_size = 1 << 32
        else:
            segment_size = 1 << 16

    try:
        segment_name = names[segment_name_index - 1]
    except IndexError:
        segment_name = b"--ERROR--"
    try:
        segment_class = names[segment_class_index - 1]
    except IndexError:
        segment_class = b"--ERROR--"
    try:
        segment_overlay_name = names[segment_overlay_name_index - 1]
    except IndexError:
        segment_overlay_name = b"--ERROR--"

    rr = "SEGDEF386" if use_32bit else "SEGDEF"
    print(f"{rr} relocatable={relocatable} alignment={segment_alignment} segment_location={segment_location} segment_offset={segment_offset} segment_size={segment_size}")
    print(f"       {segment_size=}, {segment_name_index=}, {segment_class_index=}, {segment_overlay_name_index=}")
    print(f"       {segment_name=}, {segment_class=}, {segment_overlay_name=}")
    if position != offset + size:
        logger.warning("%s: offset=0x%x size mismatch position=0x%x, expected=0x%x", rr, offset, position, offset+size)


def parse_GRPDEF(data: bytes, offset: int, size: int, names: list[bytes]):
    position = offset
    group_name_index, = struct.unpack_from("<B", data, position)
    position += 1

    segments = []
    while position < offset + size:
        item_type, = struct.unpack_from("<B", data, position)
        position += 1
        match item_type:
            case 0xff:
                item_type_name = "seg"
                segment, = struct.unpack_from("<B", data, position)
                segments.append(segment)
                position += 1
            case 0xfe:
                item_type_name = "external"
                external_index = struct.unpack_from("<B", data, position)
                position += 1
                raise NotImplementedError("Unsupported by the Microsoft Linker")
            case 0xfd:
                segment_name_index, class_name_index, overlay_name_index = struct.unpack_from("<BBB", data, position)
                position += 3
                item_type_name = "segdef"
                raise NotImplementedError("Unsupported by the Microsoft Linker")
            case 0xfb:
                ltl_data_field, maximum_group_length, group_length = struct.unpack_from("<BBB", data, position)
                position += 3
                item_type_name = "group"
                raise NotImplementedError("Unsupported by the Microsoft Linker")
            case 0xfa:
                frame_number, offset = struct.unpack_from("<BB", data, position)
                position += 2
                item_type_name = "frane"
                raise NotImplementedError("Unsupported by the Microsoft Linker")
            case _:
                raise ValueError(f"Unsupported group item type: 0x{item_type:02x}")

    group_name = names[group_name_index - 1]
    print(f"GRPDEF: {group_name} ({group_name_index}): {segments}")
    assert position == offset + size


def parse_FIXUPP(data: bytes, offset: int, size: int, use_32bit: bool):
    if use_32bit:
        raise NotImplementedError
    position = offset
    while position < offset + size:
        subrecord_hdr, = struct.unpack_from("<B", data, position)
        position += 1
        if subrecord_hdr & 0x80:
            # FIXUP record (of nearest previous LEDATA/LIDATA record
            mode = bool(subrecord_hdr & 0x40) # !: segment-relative fixup, 0: self-relative fix-up
            location = (subrecord_hdr & 0x3c) >> 2
            data_record_offset, = struct.unpack_from("<B", data, offset=position)
            position += 1
            data_record_offset |= (subrecord_hdr & 0x3) << 8

            fix_data, = struct.unpack_from("<B", data, offset=position)
            position += 1
            frame_by_thread = bool(fix_data & 0x80)
            frame_field = (fix_data >> 4) & 0x7
            if frame_by_thread:
                # frame is in thread
                frame_thread = frame_field % 4
            else:
                # frame is in this fixup subrecord
                frame_datum, = struct.unpack_from("<B", data, offset=position)
                position += 1
            target_by_thread = bool(fix_data & 0x8)
            if target_by_thread:
                target_thread = fix_data & 0x3
                # target is in this fixup subrecord
                target_datum, = struct.unpack_from("<B", data, offset=position)
                position += 1

            target_displacement_present = not bool(fix_data & 0x4)

            print(f"FIXUP record {mode=} {location=} {data_record_offset=}")
            print(f"       {is_frame_thread=} {frame=}")
            raise NotImplementedError
        else:
            # thread for subsequent use
            is_frame_thread = bool(subrecord_hdr & 0x40)  # 0 for TARGET thread, 1 for FRAME thread
            assert not bool(subrecord_hdr & 0x20), "Byte 0x20 of thread subrecord should be 0"
            thread_method = (subrecord_hdr & 0x1c) >> 2
            assert thread_method
            thread_number = subrecord_hdr & 0x3
            thread_index, = struct.unpack_from("<B", data, position)
            position += 1
            print(f"THREAD record {'FRAME' if is_frame_thread else 'TARGET'} number={thread_number}: method={thread_method} index={thread_index}")


def parse_EXTDEF(data: bytes, offset: int, size: int):
    position = offset
    externals = []
    while position < offset + size:
        name_length, = struct.unpack_from("<B", data, position)
        position += 1
        name, type_information = struct.unpack_from(f"<{name_length}sB", data, position)
        position += name_length + 1
        if type_information != 0:
            raise NotImplementedError("Don't know what to do with non-zero EXTDEF type information")
        externals.append((name, type_information))
    assert position == offset + size
    print(f"EXTDEF: {externals=}")
    return externals


def parse_LEDATA(data: bytes, offset: int, size: int, use_32bit: bool):
    position = offset
    if use_32bit:
        segment_index, enumerated_data_offset = struct.unpack_from("<HI", data, offset=position)
        position += 6
    else:
        segment_index, enumerated_data_offset = struct.unpack_from("<BH", data, offset=position)
        position += 3
    raw_data = data[position:offset+size]
    binascii.b2a_hex(raw_data)
    print(f"LEDATA: {segment_index=} {enumerated_data_offset=} raw_data={binascii.b2a_hex(raw_data)}")


def parse_PUBDEF(data: bytes, offset: int, size: int, use_32bit: bool):
    position = offset
    base_group_index, base_segment_index = struct.unpack_from("<BB", data, offset=position)
    position += 2
    # base_frame_field = None
    # if base_group_index != 0:
    #     base_frame_field, = struct.unpack_from("<H", data, offset=position)
    #     position += 2
    names = []
    while offset + size - position > 0:
        len_name, = struct.unpack_from("<B", data, offset=position)
        position += 1
        name = data[position:position+len_name]
        position += len_name
        if use_32bit:
            public_offset_field, type_index = struct.unpack_from("<IB", data, offset=position)
            position += 5
        else:
            public_offset_field, type_index = struct.unpack_from("<HB", data, offset=position)
            position += 3
        names.append((name, public_offset_field, type_index))
    print(f"PUBDEF {base_group_index=} {base_segment_index} {names=}")
    assert offset + size == position


# @dataclasses.dataclass
# class THEADR:
#     name: bytes
#
#     @classmethod
#     def parse(cls, s: bytes, offset: int) -> tuple["THEADR", int]:
#         position = offset
#         record_type, = struct.unpack_from("<B", s, position)
#         if record_type != 0x80:
#             raise WrongRecordType()
#         position += 1
#         record_length, string_length = struct.unpack_from("<HB", s, position)
#         if record_length != string_length + 2:
#             raise ValueError("THEADR: unexpected record and string length")
#         position += 3
#         name_string, = struct.unpack_from(f"<{string_length}s", s, position)
#         if not all(c < 0x80 for c in name_string):
#             raise ValueError("Non-ascii character in name")
#         position += string_length
#         checksum, = struct.unpack_from("<B", s, position)
#         position += 1
#         return cls(name=name_string), position
#
#
# def read_record(s: bytes, offset: int):
#     record_type_value, record_size = struct.unpack_from("<BH", s, offset)
#     record_type = OMFRecordType(record_type_value)
#     print(record_type.name)
#     record_checksum = sum(s[i] for i in range(offset + 3, offset + 3 + record_size))
#     if record_checksum != 0:
#         raise ValueError("Invalid checksum")


def iterate_records(data: bytes, offset: int) -> Iterator[tuple[OMFRecordType, int, int]]:
    while True:
        record_type_value, record_size = struct.unpack_from("<BH", data, offset)
        record_type = OMFRecordType(record_type_value)
        assert record_size > 0
        checksum_byte = data[offset + 3 + record_size - 1]
        if checksum_byte != 0:
            record_checksum = sum(data[i] for i in range(offset + 0, offset + 3 + record_size)) % 256
            print(f"calculated_checksum=0x{record_checksum:02x} stored_checksum=0x{checksum_byte:02x}")
            if record_checksum != 0:
                raise ValueError("Invalid checksum")
        yield record_type, offset + 3, record_size - 1
        if record_type == OMFRecordType.MODEND:
            break
        offset += 3 + record_size


# pylint: disable=too-many-public-methods
@dataclasses.dataclass
class OMFObject(Image):
    @classmethod
    def taste(
        cls, data: bytes, offset: int
    ) -> bool:
        record_iterator = iterate_records(data, offset)
        record_type, record_offset, record_size = next(record_iterator)
        # First record must be of type THEADR
        if record_type != OMFRecordType.THEADR:
            return False
        try:
            while True:
                record_type, record_offset, record_size = next(record_iterator)
        except StopIteration:
            pass
        # Last record must be of type THEADR
        if record_type != OMFRecordType.MODEND:
            return False
        return True

    @classmethod
    def from_memory(
        cls, data: bytes, offset: int, filepath: Path
    ) -> "OMFObject":
        names = []
        for record_type, record_offset, record_size in iterate_records(data, offset):
            match record_type:
                case OMFRecordType.THEADR:
                    parse_THEADR(data, record_offset, record_size)
                case OMFRecordType.COMENT:
                    parse_COMENT(data, record_offset, record_size)
                case OMFRecordType.LNAMES:
                    new_names = parse_LNAMES(data, record_offset, record_size)
                    names.extend(new_names)
                case OMFRecordType.SEGDEF | OMFRecordType.SEGDEF386:
                    parse_SEGDEF(data, record_offset, record_size, use_32bit=record_type == OMFRecordType.SEGDEF386, names=names)
                case OMFRecordType.GRPDEF:
                    parse_GRPDEF(data, record_offset, record_size, names=names)
                case OMFRecordType.FIXUPP | OMFRecordType.FIXUPP386:
                    parse_FIXUPP(data, record_offset, record_size, use_32bit=record_type == OMFRecordType.FIXUPP386)
                case OMFRecordType.EXTDEF:
                    parse_EXTDEF(data, record_offset, record_size)
                case OMFRecordType.LEDATA_1 | OMFRecordType.LEDATA_2:
                    parse_LEDATA(data, record_offset, record_size, use_32bit=record_type == OMFRecordType.LEDATA_2)
                case OMFRecordType.PUBDEF_1 | OMFRecordType.PUBDEF_2:
                    parse_PUBDEF(data, record_offset, record_size, use_32bit=record_type == OMFRecordType.PUBDEF_2)
                case _:
                    raise ValueError(record_type.name, hex(record_type.value), hex(record_offset))
