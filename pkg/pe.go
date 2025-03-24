package pe

import (
	"unsafe"
)

const DLL_PROCESS_ATTACH uint32 = 1

const DLL_THREAD_ATTACH uint32 = 2

const DLL_THREAD_DETACH uint32 = 3

const DLL_PROCESS_DETACH uint32 = 0

const TLS_OUT_OF_INDEXES uint32 = 0xFFFFFFFF

const IMAGE_NT_SIGNATURE uint32 = 0x50450000 // PE00

const NTDLL_LDRPCALLINITRT_OFFSET = 0x000199bc

type LpCallInitRoutine func(size_t uintptr, size_t1 uintptr, size_t2 uintptr) uintptr

type PLdrpCallInitRoutine func(lpCallInitRoutine, size_t1, uint32, size_t uintptr) byte

type IMAGE_DOS_HEADER struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   int32
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_RUNTIME_FUNCTION_ENTRY struct {
	BeginAddress      uint32
	EndAddress        uint32
	UnWindInfoAddress uint32
}

const IMAGE_SIZEOF_FILE_HEADER = 20
const IMAGE_FILE_RELOCS_STRIPPED = 0x0001
const IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
const IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004
const IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008
const IMAGE_FILE_AGGRESIVE_WS_TRIM = 0x0010
const IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
const IMAGE_FILE_BYTES_REVERSED_LO = 0x0080
const IMAGE_FILE_32BIT_MACHINE = 0x0100
const IMAGE_FILE_DEBUG_STRIPPED = 0x0200
const IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400
const IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800
const IMAGE_FILE_SYSTEM = 0x1000
const IMAGE_FILE_DLL = 0x2000
const IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000
const IMAGE_FILE_BYTES_REVERSED_HI = 0x8000

const IMAGE_FILE_MACHINE_I386 = 0x014c
const IMAGE_FILE_MACHINE_IA64 = 0x0200

const IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16

type IMAGE_OPTIONAL_HEADER struct {
	//
	// Standard fields.
	//

	Magic                   uint16
	MajorLinkerVersion      byte
	MinorLinkerVersion      byte
	SizeOfCode              uint32
	SizeOfInitializedData   uint32
	SizeOfUninitializedData uint32
	AddressOfEntryPoint     uint32
	BaseOfCode              uint32
	BaseOfData              uint32

	//
	// NT additional fields.
	//

	ImageBase                   uint32
	SectionAlignment            uint32
	FileAlginment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint32
	SizeOfStackCommit           uint32
	SizeOfHeapReserve           uint32
	SizeOfHeapCommit            uint32
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY
}

// Directory Entries

const IMAGE_DIRECTORY_ENTRY_EXPORT = 0          // Export Directory
const IMAGE_DIRECTORY_ENTRY_IMPORT = 1          // Import Directory
const IMAGE_DIRECTORY_ENTRY_RESOURCE = 2        // Resource Directory
const IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3       // Exception Directory
const IMAGE_DIRECTORY_ENTRY_SECURITY = 4        // Security Directory
const IMAGE_DIRECTORY_ENTRY_BASERELOC = 5       // Base Relocation Table
const IMAGE_DIRECTORY_ENTRY_DEBUG = 6           // Debug Directory
const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7    // Architecture Specific Data
const IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8       // RVA of GP
const IMAGE_DIRECTORY_ENTRY_TLS = 9             // TLS Directory
const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10    // Load Configuration Directory
const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11   // Bound Import Directory in headers
const IMAGE_DIRECTORY_ENTRY_IAT = 12            // Import Address Table
const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13   // Delay Load Import Descriptors
const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14 // COM Runtime descriptor

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_IMPORT_DESCRIPTOR struct {
	DUMMYUNIONNAME uint32
	TimeDatestamp  uint32
	ForwarderChain uint32
	Name           uint32
	FirstThunk     uint32
}

type IMAGE_IMPORT_BY_NAME struct {
	Hint uint16
	Name [1]byte
}

type IMAGE_THUNK_DATA64 struct {
	U1 uint64
}

type IMAGE_THUNK_DATA32 struct {
	U1 uint32
}

type IMAGE_OPTIONAL_HEADER64 struct {
	//
	// Standard fields.
	//

	Magic                   uint16
	MajorLinkerVersion      byte
	MinorLinkerVersion      byte
	SizeOfCode              uint32
	SizeOfInitializedData   uint32
	SizeOfUninitializedData uint32
	AddressOfEntryPoint     uint32
	BaseOfCode              uint32

	//
	// NT additional fields.
	//

	ImageBase                   uintptr
	SectionAlignment            uint32
	FileAlginment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uintptr
	SizeOfStackCommit           uintptr
	SizeOfHeapReserve           uintptr
	SizeOfHeapCommit            uintptr
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY
}

type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

type IMAGE_NT_HEADERS64 struct {
	Signature      uint16
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_NT_HEADERS struct {
	Signature      uint16
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER
}

const IMAGE_SIZEOF_SHORT_NAME = 8

type IMAGE_SECTION_HEADER struct {
	Name                 [IMAGE_SIZEOF_SHORT_NAME]byte
	Misc                 uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

const IMAGE_SCN_TYPE_NO_PAD = 0x00000008
const IMAGE_SCN_CNT_CODE = 0x00000020
const IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
const IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
const IMAGE_SCN_LNK_OTHER = 0x00000100
const IMAGE_SCN_LNK_INFO = 0x00000200
const IMAGE_SCN_LNK_REMOVE = 0x00000800
const IMAGE_SCN_LNK_COMDAT = 0x00001000
const IMAGE_SCN_NO_DEFER_SPEC_EXC = 0x00004000
const IMAGE_SCN_GPREL = 0x00008000
const IMAGE_SCN_MEM_PURGEABLE = 0x00020000
const IMAGE_SCN_MEM_LOCKED = 0x00040000
const IMAGE_SCN_MEM_PRELOAD = 0x00080000
const IMAGE_SCN_ALIGN_1BYTES = 0x00100000
const IMAGE_SCN_ALIGN_2BYTES = 0x00200000
const IMAGE_SCN_ALIGN_4BYTES = 0x00300000
const IMAGE_SCN_ALIGN_8BYTES = 0x00400000
const IMAGE_SCN_ALIGN_16BYTES = 0x00500000
const IMAGE_SCN_ALIGN_32BYTES = 0x00600000
const IMAGE_SCN_ALIGN_64BYTES = 0x00700000
const IMAGE_SCN_ALIGN_128BYTES = 0x00800000
const IMAGE_SCN_ALIGN_256BYTES = 0x00900000
const IMAGE_SCN_ALIGN_512BYTES = 0x00A00000
const IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000
const IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000
const IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000
const IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000
const IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000
const IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
const IMAGE_SCN_MEM_NOT_CACHED = 0x04000000
const IMAGE_SCN_MEM_NOT_PAGED = 0x08000000
const IMAGE_SCN_MEM_SHARED = 0x10000000
const IMAGE_SCN_MEM_EXECUTE = 0x20000000
const IMAGE_SCN_MEM_READ = 0x40000000
const IMAGE_SCN_MEM_WRITE = 0x80000000

type IMAGE_BASE_RELOCATION struct {
	VirtualAddress uint32
	SizeOfBlock    uint32
}

// Base Relocation Types
const IMAGE_REL_BASED_ABSOLUTE = 0
const IMAGE_DEBUG_TYPE_COFF = 1
const IMAGE_DEBUG_TYPE_CODEVIEW = 2
const IMAGE_DEBUG_TYPE_FPO = 3
const IMAGE_DEBUG_TYPE_MISC = 4
const IMAGE_DEBUG_TYPE_EXCEPTION = 5
const IMAGE_DEBUG_TYPE_FIXUP = 6
const IMAGE_DEBUG_TYPE_OMAP_TO_SRC = 7
const IMAGE_DEBUG_TYPE_OMAP_FROM_SRC = 8
const IMAGE_DEBUG_TYPE_BORLAND = 9
const IMAGE_DEBUG_TYPE_RESERVED10 = 10
const IMAGE_DEBUG_TYPE_CLSID = 11
const IMAGE_DEBUG_TYPE_REPRO = 16
const IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS = 20

type IMAGE_RESOURCE_DIRECTORY struct {
	Charateristics       uint32
	TimeDateStamp        uint32
	MajorVersion         uint16
	MinorVersion         uint16
	NumberOfNamedEntries uint16
	NumberOfIdEntries    uint16
}

const IMAGE_RESOURCE_NAME_IS_STRING = 0x80000000
const IMAGE_RESOURCE_DATA_IS_DIRECTORY = 0x80000000

type IMAGE_RESOURCE_DIRECTORY_ENTRY struct {
	Name         uint32
	OffsetToData uint32
}

type IMAGE_RESOURCE_DIRECTORY_STRING struct {
	Length     uint16
	NameString [1]byte
}

type IMAGE_RESOURCE_DIR_STRING_U struct {
	Length     uint16
	NameString [1]uint16
}

type IMAGE_RESOURCE_DATA_ENTRY struct {
	OffsetToData uint32
	Size         uint32
	CodePage     uint32
	Reserved     uint32
}

type IMAGE_TLS_DIRECTORY64 struct {
	StartAddressOfRawData uint64
	EndAddressOfRawData   uint64
	AddressOfIndex        uint64
	AddressOfCallBacks    uint64
	SizeOfZeroFill        uint32
	Characteristics       uint32
}

type IMAGE_TLS_DIRECTORY32 struct {
	StartAddressOfRawData uint32
	EndAddressOfRawData   uint32
	AddressOfIndex        uint32
	AddressOfCallBacks    uint32
	SizeOfZeroFill        uint32
	Characteristics       uint32
}

type IMAGE_BOUND_IMPORT_DESCRIPTOR struct {
	TimeDateStamp               uint32
	OffsetModuleName            uint16
	NumberOfModuleForwarderRefs uint16
}

type IMAGE_DELAYLOAD_DESCRIPTOR struct {
	Attributes                 uint32
	DllNameRVA                 uint32
	ModuleHandleRVA            uint32
	ImportAddressTableRVA      uint32
	ImportNameTableRVA         uint32
	BoundImportAddressTableRVA uint32
	UnloadInformationTableRVA  uint32
	TimeDateStamp              uint32
}

type PIMAGE_TLS_CALLBACKS struct {
	DllHandle uintptr
	Reason    uint32
	Reserved  uintptr
}

func IsForwarded(addressOfFunction, exportDirectoryRVA, exportDirectorySize uint32) bool {
	return addressOfFunction > exportDirectoryRVA && addressOfFunction < exportDirectoryRVA+exportDirectorySize
}

func GetSection(pe []byte, section uint16) *IMAGE_SECTION_HEADER {
	dosHeader := FillDosHeader(pe)
	fileHeader := FillFileHeader(pe, dosHeader.E_lfanew+4)
	var sectionOffset int32 = dosHeader.E_lfanew + int32(unsafe.Sizeof(IMAGE_NT_SIGNATURE)) + int32(unsafe.Sizeof(*fileHeader)) + int32(fileHeader.SizeOfOptionalHeader)
	for i := range fileHeader.NumberOfSections {
		if i == section {
			return FillSectionHeader(pe, sectionOffset)
		}
		sectionOffset += int32(unsafe.Sizeof(IMAGE_SECTION_HEADER{}))
	}
	return nil
}

func GetExportDirectory32(pe []byte) (*IMAGE_DATA_DIRECTORY, *IMAGE_EXPORT_DIRECTORY) {
	dosHeader := FillDosHeader(pe)
	optionHeader := FillOptionalHeader(pe, dosHeader.E_lfanew+4+0x14)
	exportDir := optionHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
	return &exportDir, (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(&pe[RvaToOffset(pe, exportDir.VirtualAddress)]))
}

func ExportNames(pe []byte, export *IMAGE_EXPORT_DIRECTORY) (exports []string) {
	exports = make([]string, export.NumberOfNames)
	var rvaToNameOffset uint32 = 0
	for {
		if rvaToNameOffset/4 == export.NumberOfNames {
			break
		}
		exports[rvaToNameOffset/4] = OffsetToString(pe, RvaToOffset(pe, *(*uint32)(unsafe.Pointer(&pe[RvaToOffset(pe, export.AddressOfNames)+rvaToNameOffset]))))
		rvaToNameOffset += 4
	}
	return
}

func OffsetToString(pe []byte, offset uint32) (exportName string) {
	var arrayOffset uint32 = 0
	for {
		c := pe[offset+arrayOffset]
		arrayOffset++
		if c == 0 {
			break
		}

		exportName = exportName + string(c)
	}
	return
}

func NullString(raw []byte) (v string) {
	for _, b := range raw {
		if b == 0 {
			break
		}
		v += string(b)
	}
	return
}

func PtrToString(start uintptr) string {
	var importNameOffset uintptr = 0
	var v string
	for {
		c := *(*byte)(unsafe.Pointer(start + importNameOffset))
		if c == 0 {
			break
		}
		v = v + string(c)
		importNameOffset++
	}
	return v
}

func Ordinals(pe []byte, export *IMAGE_EXPORT_DIRECTORY) (ordinals []uint16) {
	var ordinalOffset uint32
	ordinals = make([]uint16, export.NumberOfFunctions)
	for {
		if ordinalOffset/2 == export.NumberOfFunctions {
			break
		}
		ordinals[ordinalOffset/2] = (*(*uint16)(unsafe.Pointer(&pe[RvaToOffset(pe, export.AddressOfNameOrdinals+ordinalOffset)]))) + uint16(export.Base)
		ordinalOffset += 2
	}
	return
}

func GetSections32(pe []byte) *[]IMAGE_SECTION_HEADER {
	dosHeader := FillDosHeader(pe)
	fileHeader := FillFileHeader(pe, dosHeader.E_lfanew+4)
	sections := make([]IMAGE_SECTION_HEADER, fileHeader.NumberOfSections)
	var sectionOffset int32 = dosHeader.E_lfanew + 4 + 0x14 + 0xe0
	for i := range sections {
		sections[i] = *FillSectionHeader(pe, sectionOffset)
		sectionOffset += int32(unsafe.Sizeof(IMAGE_SECTION_HEADER{}))
	}
	return &sections
}

func AddressOfFunctions(pe []byte, export *IMAGE_EXPORT_DIRECTORY) (functions []uint32) {
	var addressOfFunctionsOffset uint32
	functions = make([]uint32, export.NumberOfFunctions)
	for {
		if addressOfFunctionsOffset/4 == export.NumberOfFunctions {
			break
		}
		functions[addressOfFunctionsOffset/4] = *(*uint32)(unsafe.Pointer(&pe[RvaToOffset(pe, export.AddressOfFunctions)+addressOfFunctionsOffset]))
		addressOfFunctionsOffset += 4
	}
	return
}

func RvaToOffset(pe []byte, rva uint32) uint32 {
	dosHeader := FillDosHeader(pe)
	fileHeader := FillFileHeader(pe, dosHeader.E_lfanew+4)

	for i := range fileHeader.NumberOfSections {
		currentSection := GetSection(pe, i)
		if rva >= currentSection.VirtualAddress && rva <= currentSection.VirtualAddress+currentSection.Misc {
			return currentSection.PointerToRawData + (rva - currentSection.VirtualAddress)
		}
	}
	return 0
}

func RvaToOffset64(pe []byte, rva uint64) uint64 {
	dosHeader := FillDosHeader(pe)
	fileHeader := FillFileHeader(pe, dosHeader.E_lfanew+4)

	for i := range fileHeader.NumberOfSections {
		currentSection := GetSection(pe, i)
		if rva >= uint64(currentSection.VirtualAddress) && rva <= uint64(currentSection.VirtualAddress+currentSection.Misc) {
			return uint64(currentSection.PointerToRawData) + (rva - uint64(currentSection.VirtualAddress))
		}
	}
	return 0
}

func VaToOffset(pe []byte, va uint32) uint32 {
	dosHeader := FillDosHeader(pe)
	fileHeader := FillFileHeader(pe, dosHeader.E_lfanew+4)
	optionHeader := FillOptionalHeader(pe, dosHeader.E_lfanew+4+0x14)

	rva := va - optionHeader.ImageBase

	for i := range fileHeader.NumberOfSections {
		currentSection := GetSection(pe, i)
		if rva >= currentSection.VirtualAddress && rva <= currentSection.VirtualAddress+currentSection.Misc {
			return va - optionHeader.ImageBase - currentSection.VirtualAddress + currentSection.PointerToRawData
		}
	}
	return 0
}

func VaToOffset64(pe []byte, va uint64) uint64 {
	dosHeader := FillDosHeader(pe)
	fileHeader := FillFileHeader(pe, dosHeader.E_lfanew+4)
	optionHeader := FillOptionalHeader64(pe, dosHeader.E_lfanew+4+0x14)

	rva := va - uint64(optionHeader.ImageBase)

	for i := range fileHeader.NumberOfSections {
		currentSection := GetSection(pe, i)
		if rva >= uint64(currentSection.VirtualAddress) && rva <= uint64(currentSection.VirtualAddress)+uint64(currentSection.Misc) {
			return va - uint64(optionHeader.ImageBase) - uint64(currentSection.VirtualAddress+currentSection.PointerToRawData)
		}
	}
	return 0
}

func HasNTSignature(pe []byte, offset int32) bool {
	return pe[offset] == 0x50 && pe[offset+1] == 0x45 && pe[offset+2] == 0x00 && pe[offset+3] == 0x00
}

func HasMagicNumbers(pe []byte) bool {
	return pe[0] == 0x4d && pe[1] == 0x5a
}

func FillDosHeader(pe []byte) *IMAGE_DOS_HEADER {
	return (*IMAGE_DOS_HEADER)(unsafe.Pointer(&pe[0]))
}

func FillFileHeader(pe []byte, offset int32) *IMAGE_FILE_HEADER {
	return (*IMAGE_FILE_HEADER)(unsafe.Pointer(&pe[offset]))
}

func FillOptionalHeader(pe []byte, offset int32) *IMAGE_OPTIONAL_HEADER {
	return (*IMAGE_OPTIONAL_HEADER)(unsafe.Pointer(&pe[offset]))

}

func FillOptionalHeader64(pe []byte, offset int32) *IMAGE_OPTIONAL_HEADER64 {
	return (*IMAGE_OPTIONAL_HEADER64)(unsafe.Pointer(&pe[offset]))
}

func FillSectionHeader(pe []byte, offset int32) *IMAGE_SECTION_HEADER {
	return (*IMAGE_SECTION_HEADER)(unsafe.Pointer(&pe[offset]))
}

func FillImportDescriptor(pe []byte, offset uint32) *IMAGE_IMPORT_DESCRIPTOR {
	return (*IMAGE_IMPORT_DESCRIPTOR)(unsafe.Pointer(&pe[offset]))
}

func FillThunkData32(pe []byte, offset uint32) *IMAGE_THUNK_DATA32 {
	return (*IMAGE_THUNK_DATA32)(unsafe.Pointer(&pe[offset]))
}

func FillThunkData64(pe []byte, offset uint32) *IMAGE_THUNK_DATA64 {
	return (*IMAGE_THUNK_DATA64)(unsafe.Pointer(&pe[offset]))
}

func FillImportByName(pe []byte, offset uint32) *IMAGE_IMPORT_BY_NAME {
	return (*IMAGE_IMPORT_BY_NAME)(unsafe.Pointer(&pe[offset]))
}

func GetResourceEntries(pebytes []byte, offset uint32, resourceDataDir IMAGE_DATA_DIRECTORY) []IMAGE_RESOURCE_DIRECTORY_ENTRY {
	return nil
}

func GetResourceDirectory(pebytes []byte, resourceEntry IMAGE_RESOURCE_DIRECTORY_ENTRY, resourceDataDir IMAGE_DATA_DIRECTORY) *IMAGE_RESOURCE_DIRECTORY {
	if (resourceEntry.Name & IMAGE_RESOURCE_NAME_IS_STRING) == IMAGE_RESOURCE_NAME_IS_STRING {
		return (*IMAGE_RESOURCE_DIRECTORY)(unsafe.Pointer(&pebytes[RvaToOffset(pebytes, resourceDataDir.VirtualAddress)+resourceEntry.Name&0x7FFFFFFF]))
	} else if (resourceEntry.OffsetToData & IMAGE_RESOURCE_DATA_IS_DIRECTORY) == IMAGE_RESOURCE_DATA_IS_DIRECTORY {
		return (*IMAGE_RESOURCE_DIRECTORY)(unsafe.Pointer(&pebytes[RvaToOffset(pebytes, resourceDataDir.VirtualAddress)+resourceEntry.OffsetToData&0x7FFFFFFF]))
	}
	return nil
}

func CopyMemory(dst, src uintptr, length uint32) {
	copy((*[1 << 30]byte)(unsafe.Pointer(dst))[:length], (*[1 << 30]byte)(unsafe.Pointer(src))[:length])
}

func ReadBytesFromPtr(src uintptr, length uint32) []byte {
	out := make([]byte, length)
	CopyMemory(uintptr(unsafe.Pointer(&out[0])), src, length)
	return out
}
