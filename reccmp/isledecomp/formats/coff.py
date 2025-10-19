"""
Based on the following resources:
- OSDev: https://wiki.osdev.org/COFF
- DJGPP COFF Spec: https://www.delorie.com/djgpp/doc/coff/
- file: https://www.darwinsys.com/file/
"""

import dataclasses
import datetime
import enum
from enum import IntEnum
from pathlib import Path
import struct
import typing

from .image import Image
from .pe import PEMachine, PESectionFlags
# from .pe import PECharacteristics

# pylint: disable=too-many-lines


class COFFHeaderNotFoundError(ValueError):
    """PE magic string not found."""


class UnknownCOFFMachine(ValueError):
    """The COFF object has an unknown machine architecture."""


class COFFRelocation_I386(IntEnum):
    IMAGE_REL_I386_ABSOLUTE     = 0x0000    # The relocation is ignored.
    IMAGE_REL_I386_DIR16        = 0x0001    # Not supported.
    IMAGE_REL_I386_REL16        = 0x0002    # Not supported.
    IMAGE_REL_I386_DIR32        = 0x0006    # The target’s 32-bit VA.
    IMAGE_REL_I386_DIR32NB      = 0x0007    # The target’s 32-bit RVA.
    IMAGE_REL_I386_SEG12        = 0x0009    # Not supported.
    IMAGE_REL_I386_SECTION      = 0x000A    # The 16-bit section index of the section that contains the target. This is used to support debugging information.
    IMAGE_REL_I386_SECREL       = 0x000B    # The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
    IMAGE_REL_I386_TOKEN        = 0x000C    # The CLR token.
    IMAGE_REL_I386_SECREL7      = 0x000D    # A 7-bit offset from the base of the section that contains the target.
    IMAGE_REL_I386_REL32        = 0x0014    # The 32-bit relative displacement to the target. This supports the x86 relative branch and call instructions.


class COFFRelocation_AMD64(IntEnum):        # LSB of symbol type
    IMAGE_REL_AMD64_ABSOLUTE    = 0x0000    # The relocation is ignored.
    IMAGE_REL_AMD64_ADDR64      = 0x0001    # The 64-bit VA of the relocation target.
    IMAGE_REL_AMD64_ADDR32      = 0x0002    # The 32-bit VA of the relocation target.
    IMAGE_REL_AMD64_ADDR32NB    = 0x0003    # The 32-bit address without an image base (RVA).
    IMAGE_REL_AMD64_REL32       = 0x0004    # The 32-bit relative address from the byte following the relocation.
    IMAGE_REL_AMD64_REL32_1     = 0x0005    # The 32-bit address relative to byte distance 1 from the relocation.
    IMAGE_REL_AMD64_REL32_2     = 0x0006    # The 32-bit address relative to byte distance 2 from the relocation.
    IMAGE_REL_AMD64_REL32_3     = 0x0007    # The 32-bit address relative to byte distance 3 from the relocation.
    IMAGE_REL_AMD64_REL32_4     = 0x0008    # The 32-bit address relative to byte distance 4 from the relocation.
    IMAGE_REL_AMD64_REL32_5     = 0x0009    # The 32-bit address relative to byte distance 5 from the relocation.
    IMAGE_REL_AMD64_SECTION     = 0x000A    # The 16-bit section index of the section that contains the target. This is used to support debugging information.
    IMAGE_REL_AMD64_SECREL      = 0x000B    # The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
    IMAGE_REL_AMD64_SECREL7     = 0x000C    # A 7-bit unsigned offset from the base of the section that contains the target.
    IMAGE_REL_AMD64_TOKEN       = 0x000D    # CLR tokens.
    IMAGE_REL_AMD64_SREL32      = 0x000E    # A 32-bit signed span-dependent value emitted into the object.
    IMAGE_REL_AMD64_PAIR        = 0x000F    # A pair that must immediately follow every span-dependent value.
    IMAGE_REL_AMD64_SSPAN32     = 0x0010    # A 32-bit signed span-dependent value that is applied at link time.

class COFFBaseSymbolType(enum.IntEnum): # MSB of symbol type
    IMAGE_SYM_TYPE_NULL         = 0     # No type information or unknown base type. Microsoft tools use this setting
    IMAGE_SYM_TYPE_VOID         = 1     # No valid type; used with void pointers and functions
    IMAGE_SYM_TYPE_CHAR         = 2     # A character (signed byte)
    IMAGE_SYM_TYPE_SHORT        = 3     # A 2-byte signed integer
    IMAGE_SYM_TYPE_INT          = 4     # A natural integer type (normally 4 bytes in Windows)
    IMAGE_SYM_TYPE_LONG         = 5     # A 4-byte signed integer
    IMAGE_SYM_TYPE_FLOAT        = 6     # A 4-byte floating-point number
    IMAGE_SYM_TYPE_DOUBLE       = 7     # An 8-byte floating-point number
    IMAGE_SYM_TYPE_STRUCT       = 8     # A structure
    IMAGE_SYM_TYPE_UNION        = 9     # A union
    IMAGE_SYM_TYPE_ENUM         = 10    # An enumerated type
    IMAGE_SYM_TYPE_MOE          = 11    # A member of enumeration (a specific value)
    IMAGE_SYM_TYPE_BYTE         = 12    # A byte; unsigned 1-byte integer
    IMAGE_SYM_TYPE_WORD         = 13    # A word; unsigned 2-byte integer
    IMAGE_SYM_TYPE_UINT         = 14    # An unsigned integer of natural size (normally, 4 bytes)
    IMAGE_SYM_TYPE_DWORD        = 15    # An unsigned 4-byte integer


class COFFComplexSymbolType(IntEnum):
    IMAGE_SYM_DTYPE_NULL        = 0	    # No derived type; the symbol is a simple scalar variable.
    IMAGE_SYM_DTYPE_POINTER     = 1	    # The symbol is a pointer to base type.
    IMAGE_SYM_DTYPE_FUNCTION    = 2	    # The symbol is a function that returns a base type.
    IMAGE_SYM_DTYPE_ARRAY       = 3	    # The symbol is an array of base type.


class COFFMicrosoftSymbolType(IntEnum):
    IMAGE_SYM_TYPE_NOT_FUNCTION = 0
    IMAGE_SYM_TYPE_FUNCTION     = 32


class COFFSymbolStorageClass(IntEnum):           # Description/interpretation of the `value` field
    IMAGE_SYM_CLASS_END_OF_FUNCTION     = -1        # A special symbol that represents the end of function, for debugging purposes.
    IMAGE_SYM_CLASS_NULL                = 0x0000    # No assigned storage class.
    IMAGE_SYM_CLASS_AUTOMATIC           = 0x0001    # The automatic (stack) variable. The Value field specifies the stack frame offset.
    IMAGE_SYM_CLASS_EXTERNAL            = 0x0002    # A value that Microsoft tools use for external symbols. The Value field indicates the size if the section number is IMAGE_SYM_UNDEFINED (0). If the section number is not zero, then the Value field specifies the offset within the section.
    IMAGE_SYM_CLASS_STATIC              = 0x0003    # The offset of the symbol within the section. If the Value field is zero, then the symbol represents a section name.
    IMAGE_SYM_CLASS_REGISTER            = 0x0004    # A register variable. The Value field specifies the register number.
    IMAGE_SYM_CLASS_EXTERNAL_DEF        = 0x0005    # A symbol that is defined externally.
    IMAGE_SYM_CLASS_LABEL               = 0x0006    # A code label that is defined within the module. The Value field specifies the offset of the symbol within the section.
    IMAGE_SYM_CLASS_UNDEFINED_LABEL     = 0x0007    # A reference to a code label that is not defined.
    IMAGE_SYM_CLASS_MEMBER_OF_STRUCT    = 0x0008    # The structure member. The Value field specifies the nth member.
    IMAGE_SYM_CLASS_ARGUMENT            = 0x0009    # A formal argument (parameter) of a function. The Value field specifies the nth argument.
    IMAGE_SYM_CLASS_STRUCT_TAG          = 0x000A    # The structure tag-name entry.
    IMAGE_SYM_CLASS_MEMBER_OF_UNION     = 0x000B    # A union member. The Value field specifies the nth member.
    IMAGE_SYM_CLASS_UNION_TAG           = 0x000C    # The Union tag-name entry.
    IMAGE_SYM_CLASS_TYPE_DEFINITION     = 0x000D    # A Typedef entry.
    IMAGE_SYM_CLASS_UNDEFINED_STATIC    = 0x000E    # A static data declaration.
    IMAGE_SYM_CLASS_ENUM_TAG            = 0x000F    # An enumerated type tagname entry.
    IMAGE_SYM_CLASS_MEMBER_OF_ENUM      = 0x0010    # A member of an enumeration. The Value field specifies the nth member.
    IMAGE_SYM_CLASS_REGISTER_PARAM      = 0x0011    # A register parameter.
    IMAGE_SYM_CLASS_BIT_FIELD           = 0x0012    # A bit-field reference. The Value field specifies the nth bit in the bit field.
    IMAGE_SYM_CLASS_FAR_EXTERNAL        = 0x0044    #
    IMAGE_SYM_CLASS_BLOCK               = 0x0064    # A .bb (beginning of block) or .eb (end of block) record. The Value field is the relocatable address of the code location.
    IMAGE_SYM_CLASS_FUNCTION            = 0x0065    # A value that Microsoft tools use for symbol records that define the extent of a function: begin function (.bf), end function (.ef), and lines in function (.lf). For .lf records, the Value field gives the number of source lines in the function. For .ef records, the Value field gives the size of the function code.
    IMAGE_SYM_CLASS_END_OF_STRUCT       = 0x0066    # An end-of-structure entry.
    IMAGE_SYM_CLASS_FILE                = 0x0067    # A value that Microsoft tools, as well as traditional COFF format, use for the source-file symbol record. The symbol is followed by auxiliary records that name the file.
    IMAGE_SYM_CLASS_SECTION             = 0x0068    # A definition of a section (Microsoft tools use STATIC storage class instead).
    IMAGE_SYM_CLASS_WEAK_EXTERNAL       = 0x0069    # A weak external.
    IMAGE_SYM_CLASS_CLR_TOKEN           = 0x006B    # A CLR token symbol. The name is an ASCII string that consists of the hexadecimal value of the token. (Object Only)


class COFFSpecialSymbolSection(IntEnum):
    IMAGE_SYM_UNDEFINED     = 0
    IMAGE_SYM_ABSOLUTE      = -1
    IMAGE_SYM_DEBUG         = -2
    IMAGE_SYM_SECTION_MAX   = 0xFEFF

class COFFComdatSelect(IntEnum):
    IMAGE_COMDAT_SELECT_NODUPLICATES    =  1
    IMAGE_COMDAT_SELECT_ANY             =  2
    IMAGE_COMDAT_SELECT_SAME_SIZE       =  3
    IMAGE_COMDAT_SELECT_EXACT_MATCH     =  4
    IMAGE_COMDAT_SELECT_ASSOCIATIVE     =  5
    IMAGE_COMDAT_SELECT_LARGEST         =  6
    IMAGE_COMDAT_SELECT_NEWEST          =  7


@dataclasses.dataclass(frozen=True)
class COFFRelocation:
    virtual_address: int        # The address of the item to which relocation is applied. This is the offset from the beginning of the section, plus the value of the section’s RVA/Offset field.
    symbol_table_index: int     # A zero-based index into the symbol table. This symbol gives the address that is to be used for the relocation. If the specified symbol has section storage class, then the symbol’s address is the address with the first section of the same name.
    type: COFFRelocation_I386 | COFFRelocation_I386   # A value that indicates the kind of relocation that should be performed.

    @classmethod
    def from_memory(cls, data: bytes, offset: int, count: int, machine: PEMachine) -> list["COFFRelocation"]:
        match machine:
            case PEMachine.IMAGE_FILE_MACHINE_I386:
                relocator = COFFRelocation_I386
            case PEMachine.IMAGE_FILE_MACHINE_AMD64:
                relocator = COFFRelocation_AMD64
            case _:
                raise NotImplementedError(f"Missing relocation support (machine={machine.name})")
        relocations = []
        o = offset
        for _ in range(count):
            r_vaddr, r_symndx, r_type = struct.unpack_from("<IIH", data, offset=o)
            relocations.append(cls(r_vaddr, r_symndx, relocator(r_type)))
            o += 10
        return relocations


@dataclasses.dataclass(frozen=True)
class COFFVirtualAddressLine:
    virtual_address: int
    line: int


@dataclasses.dataclass(frozen=True)
class COFFSymbolLines:
    symbol_index: int
    lines: list[COFFVirtualAddressLine] = dataclasses.field(default_factory=list)

    @classmethod
    def from_memory(cls, data: bytes, offset: int, count: int) -> list["COFFSymbolLines"]:
        result = []
        current_symbol = None
        for _ in range(count):
            symndx_vaddr, lnno = struct.unpack_from("<IH", data, offset=offset)
            if lnno == 0:
                current_symbol = COFFSymbolLines(symbol_index=symndx_vaddr)
                result.append(current_symbol)
            else:
                assert current_symbol is not None
                current_symbol.lines.append(COFFVirtualAddressLine(virtual_address=symndx_vaddr, line=lnno))
            offset += 6
        return result

@dataclasses.dataclass(frozen=True)
class COFFFileHeader:
    machine: PEMachine
    number_of_sections: int
    time_date_stamp: int
    pointer_to_symbol_table: int
    number_of_symbols: int
    size_of_optional_header: int
    characteristics: int            # Target dependent

    @classmethod
    def from_memory(cls, data: bytes, offset: int) -> tuple["COFFFileHeader", int]:
        if not cls.taste(data, offset):
            raise COFFHeaderNotFoundError
        struct_fmt = "<2H3I2H"
        items = list(struct.unpack_from(struct_fmt, data, offset=offset))
        offset += struct.calcsize(struct_fmt)
        try:
            items[0] = PEMachine(items[0])
        except ValueError as e:
            raise UnknownCOFFMachine(f"0x{items[0]:x}") from e
        items[2] = datetime.datetime.fromtimestamp(items[2])
        return cls(*items), offset

    @classmethod
    def taste(cls, data: bytes, offset: int) -> bool:
        if len(data) - offset < 20:
            return False
        machine_int, = struct.unpack_from("<H", data, offset=offset)
        try:
            PEMachine(machine_int)
        except ValueError:
            return False
        return True


class COFFStringTable:
    def __init__(self, raw_table: bytes):
        self.raw_table = raw_table

    def get_string_at(self, start: int) -> None | bytes:
        if start > len(self.raw_table):
            raise IndexError
        end = self.raw_table.find(0, start)
        if end == -1:
            return None
        return self.raw_table[start:end]

    def items(self) -> typing.Iterator[tuple[int, bytes]]:
        string_start = 4
        while True:
            string_end = self.raw_table.find(0, string_start)
            if string_end == -1:
                yield string_start, self.raw_table[string_start:]
                break
            else:
                yield string_start, self.raw_table[string_start:string_end]
            string_start = string_end + 1
            if string_start >= len(self.raw_table):
                break

    def values(self) -> typing.Iterator[bytes]:
        for _, s in self.items():
            yield s

    @classmethod
    def from_memory(cls, data: bytes, offset: int) -> "COFFStringTable":
        string_table_len, = struct.unpack_from("<I", data, offset=offset)
        if offset + string_table_len < len(data):
            raise ValueError("String table incomplete")
        # Offsets of zero are legal and will result in a zero-length string because of these four zeros
        raw_table = b"\x00\x00\x00\x00" + data[offset+4:offset+string_table_len]
        return cls(raw_table)


@dataclasses.dataclass(frozen=True)
class COFFSectionHeader:
    name: bytes
    virtual_size: int               # Should be set to zero for object files
    virtual_address: int            # For object files, this field is the address of the first byte before relocation is applied; for simplicity, compilers should set this to zero. Otherwise, it is an arbitrary value that is subtracted from offsets during relocation.
    size_of_raw_data: int           # The size of the section (for object files) or the size of the initialized data on disk (for image files).
    pointer_to_raw_data: int        # The size of the section (for object files), When a section contains only uninitialized data, this field should be zero.
    pointer_to_relocations: int
    pointer_to_linenumbers: int
    number_of_relocations: int
    number_of_linenumbers: int
    characteristics: PESectionFlags

    @classmethod
    def from_memory(cls, data: bytes, offset: int, string_table: COFFStringTable) -> tuple["COFFSectionHeader", int]:
        fmt = "<8s6I2HI"
        members = list(struct.unpack_from(fmt, data, offset=offset))
        # name
        if members[0] == ord(b'/'):
            members[0] = string_table.get_string_at(int(members[0][1:].rstrip(b"\x00").decode()))
        else:
            members[0] = members[0].rstrip(b"\x00")
        members[9] = PESectionFlags(members[9])
        offset += struct.calcsize(fmt)
        result = cls(*members)
        assert result.virtual_size == 0, "VirtualSize of a section in COFF object must be zero"
        assert result.virtual_address == 0, "VirtualAddress of a section in COFF object must be zero"
        return result, offset


@dataclasses.dataclass
class COFFSection:
    index: int
    header: COFFSectionHeader
    relocations: list[COFFRelocation]
    linenumbers: list[COFFSymbolLines]

    @property
    def name(self) -> bytes:
        return self.header.name

@dataclasses.dataclass()
class COFFSymbol:
    name: bytes
    value: int
    section_number: int
    type: COFFMicrosoftSymbolType
    storage_class: COFFSymbolStorageClass
    number_of_aux_symbols: int
    aux: int | bytes

    index: int

    SYMBOL_SIZE = 18

    @classmethod
    def from_memory(cls, data: bytes, offset: int, symbol_index: int, sections: list[COFFSection], string_table: COFFStringTable) -> tuple["COFFSymbol", int]:
        format = "<8si2h2B"
        assert struct.calcsize(format) == cls.SYMBOL_SIZE
        name, value, section_number, symbol_type, storage_class, number_of_aux_symbols = struct.unpack_from(format, data, offset=offset)
        offset += cls.SYMBOL_SIZE
        symbol_type = COFFMicrosoftSymbolType(symbol_type)

        storage_class = COFFSymbolStorageClass(storage_class)
        # Although the traditional COFF format uses many storage-class values,
        # Microsoft tools rely on Visual C++ debug format for most symbolic
        # information and generally use only four storage-class values:
        # EXTERNAL (2), STATIC (3), FUNCTION (101), and FILE (103).
        assert storage_class in (
            COFFSymbolStorageClass.IMAGE_SYM_CLASS_NULL,  # Added
            COFFSymbolStorageClass.IMAGE_SYM_CLASS_EXTERNAL,
            COFFSymbolStorageClass.IMAGE_SYM_CLASS_STATIC,
            COFFSymbolStorageClass.IMAGE_SYM_CLASS_FUNCTION,
            COFFSymbolStorageClass.IMAGE_SYM_CLASS_FILE,
        )
        aux = None
        name_zeroes, name_string_table = struct.unpack("<II", name)
        if name_zeroes == 0:
            name = string_table.get_string_at(name_string_table)
        name = name.rstrip(b"\x00")
        if number_of_aux_symbols != 0:
            match storage_class:
                case COFFSymbolStorageClass.IMAGE_SYM_CLASS_FILE:
                    # file path
                    filepath, = struct.unpack_from(f"<{18*number_of_aux_symbols}s", data, offset=offset)
                    filepath = filepath.rstrip(b"\x00")
                    aux = filepath,
                case COFFSymbolStorageClass.IMAGE_SYM_CLASS_EXTERNAL:
                    # External function
                    assert symbol_type == COFFMicrosoftSymbolType.IMAGE_SYM_TYPE_FUNCTION and section_number > 0
                    assert number_of_aux_symbols == 1

                    tag_index, total_size, pointer_line_number, pointer_next_function, _ = struct.unpack_from("<IIIIH", data, offset=offset)
                    aux = tag_index, total_size, pointer_line_number, pointer_next_function
                case COFFSymbolStorageClass.IMAGE_SYM_CLASS_FUNCTION:
                    # Function data
                    assert name in (b".bf", b".lf", b".ef")
                    assert number_of_aux_symbols == 1
                    _, line_number, _, pointer_next_function, _ = struct.unpack_from("<IIIIH",data, offset=offset)
                    aux = line_number, pointer_next_function
                case COFFSymbolStorageClass.IMAGE_SYM_CLASS_WEAK_EXTERNAL:
                    # Weak symbol
                    assert section_number == COFFSpecialSymbolSection.IMAGE_SYM_UNDEFINED.value
                    assert value == 0
                    assert number_of_aux_symbols == 1
                    tag_index_sym2, characteristics = struct.unpack_from("<II", data, offset)
                    raise NotImplementedError("IMAGE_SYM_CLASS_WEAK_EXTERNAL")
                case COFFSymbolStorageClass.IMAGE_SYM_CLASS_STATIC:
                    if symbol_type == 0:
                        # Section info
                        assert number_of_aux_symbols == 1
                        assert any(name == s.name for s in sections)
                        section_length, count_relocs, count_linenums, comdat_checksum, comdat_sector, comdat_selection = struct.unpack_from("<IHHIHB", data, offset=offset)
                        aux = section_length, count_relocs, count_linenums, comdat_checksum, comdat_sector, comdat_selection
                    else:
                        # Static function
                        assert number_of_aux_symbols == 1

                        tag_index, total_size, pointer_line_number, pointer_next_function, _ = struct.unpack_from("<IIIIH", data, offset=offset)
                        aux = tag_index, total_size, pointer_line_number, pointer_next_function
                case _:
                    assert False
        offset += number_of_aux_symbols * cls.SYMBOL_SIZE
        sym = cls(name, value, section_number, symbol_type, storage_class, number_of_aux_symbols, aux, index=symbol_index)
        return sym, offset



@dataclasses.dataclass
class COFFObject(Image):
    header: COFFFileHeader
    sections: list[COFFSection]
    symbols: dict[int, COFFSymbol]
    string_table: COFFStringTable

    @classmethod
    def from_memory(
        cls, data: bytes, offset: int, filepath: Path
    ) -> "COFFObject":
        header, section_offset = COFFFileHeader.from_memory(data, offset)
        sections: list[COFFSection] = []
        string_table_offset = offset + header.pointer_to_symbol_table + header.number_of_symbols * COFFSymbol.SYMBOL_SIZE
        string_table = COFFStringTable.from_memory(data=data, offset=string_table_offset)
        for section_index in range(header.number_of_sections):
            section_header, section_offset = COFFSectionHeader.from_memory(data, section_offset, string_table=string_table)
            section_linenumbers = COFFSymbolLines.from_memory(
                data=data,
                offset=offset + section_header.pointer_to_linenumbers,
                count=section_header.number_of_linenumbers,
            )
            section = COFFSection(
                index=section_index,
                header=section_header,
                relocations=[],
                linenumbers=section_linenumbers,
            )
            sections.append(section)

        symbols: dict[int, COFFSymbol] = {}
        symbol_index = 0
        symbol_offset = offset + header.pointer_to_symbol_table
        while symbol_index < header.number_of_symbols:
            symbol, symbol_offset = COFFSymbol.from_memory(data, symbol_offset, symbol_index=symbol_index, sections=sections, string_table=string_table)
            symbols[symbol_index] = symbol
            symbol_index += 1 + symbol.number_of_aux_symbols

        for section in sections:
            section_relocations = COFFRelocation.from_memory(
                data=data,
                offset=offset + section.header.pointer_to_relocations,
                count=section.header.number_of_relocations,
                machine=header.machine,
            )
            section.relocations = section_relocations

        return cls(
            filepath=filepath,
            data=data,
            view=memoryview(data),
            header=header,
            sections=sections,
            symbols=symbols,
            string_table=string_table,
        )

    @classmethod
    def taste(cls, data: bytes, offset: int) -> bool:
        return COFFFileHeader.taste(data, offset)
