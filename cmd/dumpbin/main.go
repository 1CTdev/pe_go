package main

import (
	"encoding/binary"
	"fmt"
	"os"
	pe "pe/pkg"
	"text/tabwriter"
	"unsafe"
)

func main() {
	pebytes, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println("[-]", err.Error())
		return
	}

	if pe.HasMagicNumbers(pebytes) {
		dosHeader := pe.FillDosHeader(pebytes)
		printDosHeader(*dosHeader)

		if pe.HasNTSignature(pebytes, dosHeader.E_lfanew) {
			fileHeader := pe.FillFileHeader(pebytes, dosHeader.E_lfanew+4)
			printFileHeader(*fileHeader)

			var directory [16]pe.IMAGE_DATA_DIRECTORY

			if fileHeader.SizeOfOptionalHeader == uint16(unsafe.Sizeof(pe.IMAGE_OPTIONAL_HEADER{})) {
				optionHeader := pe.FillOptionalHeader(pebytes, dosHeader.E_lfanew+4+0x14)
				printOptionHeader(*optionHeader)
				directory = optionHeader.DataDirectory

			} else if fileHeader.SizeOfOptionalHeader == 0xF0 {
				optionHeader64 := pe.FillOptionalHeader64(pebytes, dosHeader.E_lfanew+4+0x14)
				printOptionHeader64(*optionHeader64)
				directory = optionHeader64.DataDirectory
			} else {
				fmt.Println("[-] invalid fileheader size")
				return
			}

			var sectionOffset int32 = dosHeader.E_lfanew + 4 + 0x14 + int32(fileHeader.SizeOfOptionalHeader)
			for range fileHeader.NumberOfSections {
				sectionheader := pe.FillSectionHeader(pebytes, sectionOffset)
				printSectionHeader(*sectionheader)
				sectionOffset += int32(unsafe.Sizeof(pe.IMAGE_SECTION_HEADER{}))
			}

			delayImportDir := directory[pe.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]
			if delayImportDir.Size != 0 {
				printDelayedImportDirectory(pebytes, delayImportDir)
			}

			tlsDir := directory[pe.IMAGE_DIRECTORY_ENTRY_TLS]
			if tlsDir.Size != 0 {
				printTLSDirectory(fileHeader.SizeOfOptionalHeader, pebytes, tlsDir)
			}

			resourceDir := directory[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE]
			if resourceDir.Size != 0 {
				printResourceDirectory(pebytes, resourceDir)
			}

			iatDir := directory[pe.IMAGE_DIRECTORY_ENTRY_IAT]
			if iatDir.Size != 0 {
				printIATDirectory(fileHeader.SizeOfOptionalHeader, pebytes, iatDir)
			}

			relocDir := directory[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC]
			if relocDir.Size != 0 {
				printRelocationDirectory(pebytes, relocDir)
			}

			importDir := directory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
			if importDir.Size != 0 {
				printImportDirectory(fileHeader.SizeOfOptionalHeader, pebytes, importDir)
			}

			exportDir, export := pe.GetExportDirectory32(pebytes)
			if exportDir.Size != 0 {
				printExportDirectory(pebytes, *export)

				ordinals := pe.Ordinals(pebytes, export)
				exportNames := pe.ExportNames(pebytes, export)
				addressOfFunctions := pe.AddressOfFunctions(pebytes, export)

				printExports(pebytes, *exportDir, *export, ordinals, exportNames, addressOfFunctions)
			}

			exceptionDir := directory[pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION]
			if exceptionDir.Size != 0 {
				printExceptionDirectory(pebytes, exceptionDir)
			}

		} else {
			fmt.Println("[-] didn't find NT Signature")
		}
	} else {
		fmt.Println("[-] didn't find magic numbers")
	}
}

func printOptionHeader(optionHeader pe.IMAGE_OPTIONAL_HEADER) {
	writer := tabwriter.NewWriter(os.Stdout, 1, 1, 5, ' ', 0)
	fmt.Fprintf(writer, "[+] optional header\n")
	fmt.Fprintf(writer, "%s\t%x\n", "Magic", optionHeader.Magic)
	fmt.Fprintf(writer, "%s\t%x\n", "MajorLinkerVersion", optionHeader.MajorLinkerVersion)
	fmt.Fprintf(writer, "%s\t%x\n", "MinorLinkerVersion", optionHeader.MinorLinkerVersion)
	fmt.Fprintf(writer, "%s\t%x\n", "SizeOfCode", optionHeader.SizeOfCode)
	fmt.Fprintf(writer, "%s\t%x\n", "SizeOfInitializedData", optionHeader.SizeOfInitializedData)
	fmt.Fprintf(writer, "%s\t%x\n", "SizeOfUnInitalizedData", optionHeader.SizeOfUninitializedData)
	fmt.Fprintf(writer, "%s\t%x\n", "AddressOfEntryPoint", optionHeader.AddressOfEntryPoint)
	fmt.Fprintf(writer, "%s\t%x\n", "BaseOfCode", optionHeader.BaseOfCode)
	fmt.Fprintf(writer, "\n")
	fmt.Fprintf(writer, "%s\t%x\n", "ImageBase", optionHeader.ImageBase)
	fmt.Fprintf(writer, "%s\t%x\n", "SectionAlignment", optionHeader.SectionAlignment)
	fmt.Fprintf(writer, "%s\t%x\n", "FileAlginment", optionHeader.FileAlginment)
	fmt.Fprintf(writer, "%s\t%x\n", "MajorOperatingSystemVersion", optionHeader.MajorOperatingSystemVersion)
	fmt.Fprintf(writer, "%s\t%x\n", "MinorOperatingSystemVersion", optionHeader.MinorOperatingSystemVersion)
	fmt.Fprintf(writer, "%s\t%x\n", "MajorImageVersion", optionHeader.MajorImageVersion)
	fmt.Fprintf(writer, "%s\t%x\n", "MinorImageVersion", optionHeader.MinorImageVersion)
	fmt.Fprintf(writer, "%s\t%x\n", "MajorSubsystemVersion", optionHeader.MajorSubsystemVersion)
	fmt.Fprintf(writer, "%s\t%x\n", "MinorSubSystemVersion", optionHeader.MinorSubsystemVersion)
	fmt.Fprintf(writer, "%s\t%x\n", "Win32VersionValue", optionHeader.Win32VersionValue)
	fmt.Fprintf(writer, "%s\t%x\n", "SizeOfImage", optionHeader.SizeOfImage)
	fmt.Fprintf(writer, "%s\t%x\n", "SizeOfHeaders", optionHeader.SizeOfHeaders)
	fmt.Fprintf(writer, "%s\t%x\n", "CheckSum", optionHeader.CheckSum)
	fmt.Fprintf(writer, "%s\t%x\n", "Subsystem", optionHeader.Subsystem)
	fmt.Fprintf(writer, "%s\t%x\n", "DllCharacteristics", optionHeader.DllCharacteristics)
	fmt.Fprintf(writer, "%s\t%x\n", "SizeOfStackReserve", optionHeader.SizeOfStackReserve)
	fmt.Fprintf(writer, "%s\t%x\n", "SizeOfStackCommit", optionHeader.SizeOfStackCommit)
	fmt.Fprintf(writer, "%s\t%x\n", "SizeOfHeapReserve", optionHeader.SizeOfHeapReserve)
	fmt.Fprintf(writer, "%s\t%x\n", "SizeOfHeapCommit", optionHeader.SizeOfHeapCommit)
	fmt.Fprintf(writer, "%s\t%x\n", "LoaderFlags", optionHeader.LoaderFlags)
	fmt.Fprintf(writer, "%s\t%x\n", "NumberOfRvaAndSizes", optionHeader.NumberOfRvaAndSizes)
	fmt.Fprintf(writer, "\n")
	writer.Flush()

	for i := range optionHeader.DataDirectory {
		switch i {
		case 0:
			fmt.Fprintln(writer, "Export Directory")
		case 1:
			fmt.Fprintln(writer, "Import Directory")
		case 2:
			fmt.Fprintln(writer, "Resource Directory")
		case 3:
			fmt.Fprintln(writer, "Exception Directory")
		case 4:
			fmt.Fprintln(writer, "Security Directory")
		case 5:
			fmt.Fprintln(writer, "Base Relocation Table")
		case 6:
			fmt.Fprintln(writer, "Debug Directory")
		case 7:
			fmt.Fprintln(writer, "Architecture Specific Data")
		case 8:
			fmt.Fprintln(writer, "RVA of GP")
		case 9:
			fmt.Fprintln(writer, "TLS Directory")
		case 10:
			fmt.Fprintln(writer, "Load Configuration Directory")
		case 11:
			fmt.Fprintln(writer, "Bound Import Directory")
		case 12:
			fmt.Fprintln(writer, "Import Address Table")
		case 13:
			fmt.Fprintln(writer, "Delay Load Import Descriptors")
		case 14:
			fmt.Fprintln(writer, "COM Runtime descriptor")
		default:
			continue
		}
		fmt.Fprintf(writer, "\t%s\t%x\n", "VirtualAddress", optionHeader.DataDirectory[i].VirtualAddress)
		fmt.Fprintf(writer, "\t%s\t%x\n", "Size", optionHeader.DataDirectory[i].Size)
	}
	fmt.Fprintf(writer, "\n")
	writer.Flush()
}

func printOptionHeader64(optionHeader pe.IMAGE_OPTIONAL_HEADER64) {
	writer := tabwriter.NewWriter(os.Stdout, 1, 1, 5, ' ', 0)
	fmt.Fprintf(writer, "[+] optional header\n")
	fmt.Fprintf(writer, "%s\t%x\n", "Magic", optionHeader.Magic)
	fmt.Fprintf(writer, "%s\t%x\n", "MajorLinkerVersion", optionHeader.MajorLinkerVersion)
	fmt.Fprintf(writer, "%s\t%x\n", "MinorLinkerVersion", optionHeader.MinorLinkerVersion)
	fmt.Fprintf(writer, "%s\t%x\n", "SizeOfCode", optionHeader.SizeOfCode)
	fmt.Fprintf(writer, "%s\t%x\n", "SizeOfInitializedData", optionHeader.SizeOfInitializedData)
	fmt.Fprintf(writer, "%s\t%x\n", "SizeOfUnInitalizedData", optionHeader.SizeOfUninitializedData)
	fmt.Fprintf(writer, "%s\t%x\n", "AddressOfEntryPoint", optionHeader.AddressOfEntryPoint)
	fmt.Fprintf(writer, "%s\t%x\n", "BaseOfCode", optionHeader.BaseOfCode)
	fmt.Fprintf(writer, "\n")
	fmt.Fprintf(writer, "%s\t%x\n", "ImageBase", optionHeader.ImageBase)
	fmt.Fprintf(writer, "%s\t%x\n", "SectionAlignment", optionHeader.SectionAlignment)
	fmt.Fprintf(writer, "%s\t%x\n", "FileAlginment", optionHeader.FileAlginment)
	fmt.Fprintf(writer, "%s\t%x\n", "MajorOperatingSystemVersion", optionHeader.MajorOperatingSystemVersion)
	fmt.Fprintf(writer, "%s\t%x\n", "MinorOperatingSystemVersion", optionHeader.MinorOperatingSystemVersion)
	fmt.Fprintf(writer, "%s\t%x\n", "MajorImageVersion", optionHeader.MajorImageVersion)
	fmt.Fprintf(writer, "%s\t%x\n", "MinorImageVersion", optionHeader.MinorImageVersion)
	fmt.Fprintf(writer, "%s\t%x\n", "MajorSubsystemVersion", optionHeader.MajorSubsystemVersion)
	fmt.Fprintf(writer, "%s\t%x\n", "MinorSubSystemVersion", optionHeader.MinorSubsystemVersion)
	fmt.Fprintf(writer, "%s\t%x\n", "Win32VersionValue", optionHeader.Win32VersionValue)
	fmt.Fprintf(writer, "%s\t%x\n", "SizeOfImage", optionHeader.SizeOfImage)
	fmt.Fprintf(writer, "%s\t%x\n", "SizeOfHeaders", optionHeader.SizeOfHeaders)
	fmt.Fprintf(writer, "%s\t%x\n", "CheckSum", optionHeader.CheckSum)
	fmt.Fprintf(writer, "%s\t%x\n", "Subsystem", optionHeader.Subsystem)
	fmt.Fprintf(writer, "%s\t%x\n", "DllCharacteristics", optionHeader.DllCharacteristics)
	fmt.Fprintf(writer, "%s\t%x\n", "SizeOfStackReserve", optionHeader.SizeOfStackReserve)
	fmt.Fprintf(writer, "%s\t%x\n", "SizeOfStackCommit", optionHeader.SizeOfStackCommit)
	fmt.Fprintf(writer, "%s\t%x\n", "SizeOfHeapReserve", optionHeader.SizeOfHeapReserve)
	fmt.Fprintf(writer, "%s\t%x\n", "SizeOfHeapCommit", optionHeader.SizeOfHeapCommit)
	fmt.Fprintf(writer, "%s\t%x\n", "LoaderFlags", optionHeader.LoaderFlags)
	fmt.Fprintf(writer, "%s\t%x\n", "NumberOfRvaAndSizes", optionHeader.NumberOfRvaAndSizes)
	fmt.Fprintf(writer, "\n")
	writer.Flush()

	for i := range optionHeader.DataDirectory {
		switch i {
		case 0:
			fmt.Fprintln(writer, "Export Directory")
		case 1:
			fmt.Fprintln(writer, "Import Directory")
		case 2:
			fmt.Fprintln(writer, "Resource Directory")
		case 3:
			fmt.Fprintln(writer, "Exception Directory")
		case 4:
			fmt.Fprintln(writer, "Security Directory")
		case 5:
			fmt.Fprintln(writer, "Base Relocation Table")
		case 6:
			fmt.Fprintln(writer, "Debug Directory")
		case 7:
			fmt.Fprintln(writer, "Architecture Specific Data")
		case 8:
			fmt.Fprintln(writer, "RVA of GP")
		case 9:
			fmt.Fprintln(writer, "TLS Directory")
		case 10:
			fmt.Fprintln(writer, "Load Configuration Directory")
		case 11:
			fmt.Fprintln(writer, "Bound Import Directory")
		case 12:
			fmt.Fprintln(writer, "Import Address Table")
		case 13:
			fmt.Fprintln(writer, "Delay Load Import Descriptors")
		case 14:
			fmt.Fprintln(writer, "COM Runtime descriptor")
		default:
			continue
		}
		fmt.Fprintf(writer, "\t%s\t%x\n", "VirtualAddress", optionHeader.DataDirectory[i].VirtualAddress)
		fmt.Fprintf(writer, "\t%s\t%x\n", "Size", optionHeader.DataDirectory[i].Size)
	}
	fmt.Fprintf(writer, "\n")
	writer.Flush()
}

func printFileHeader(fileHeader pe.IMAGE_FILE_HEADER) {
	fmt.Println("[+] NT file header")
	writer := tabwriter.NewWriter(os.Stdout, 1, 1, 5, ' ', 0)
	fmt.Fprintf(writer, "%s\t%x\n", "Machine", fileHeader.Machine)
	fmt.Fprintf(writer, "%s\t%x\n", "NumberOfSections", fileHeader.NumberOfSections)
	fmt.Fprintf(writer, "%s\t%x\n", "TimeDateStamp", fileHeader.TimeDateStamp)
	fmt.Fprintf(writer, "%s\t%x\n", "PointerToSymbolTable", fileHeader.PointerToSymbolTable)
	fmt.Fprintf(writer, "%s\t%x\n", "NumberOfSymbols", fileHeader.NumberOfSymbols)
	fmt.Fprintf(writer, "%s\t%x\n", "SizeOfOptionalHeader", fileHeader.SizeOfOptionalHeader)
	fmt.Fprintf(writer, "%s\t%x\n", "Characteristics", fileHeader.Characteristics)
	fmt.Fprintf(writer, "\n")
	writer.Flush()
}

func printDosHeader(dosHeader pe.IMAGE_DOS_HEADER) {
	fmt.Println("[+] DOS header")
	writer := tabwriter.NewWriter(os.Stdout, 1, 1, 5, ' ', 0)
	fmt.Fprintf(writer, "%s\t%c%c\n", "e_magic", byte(dosHeader.E_magic), byte(dosHeader.E_magic>>8))
	fmt.Fprintf(writer, "%s\t%x\n", "e_cblp", dosHeader.E_cblp)
	fmt.Fprintf(writer, "%s\t%x\n", "e_cp", dosHeader.E_cp)
	fmt.Fprintf(writer, "%s\t%x\n", "e_crlc", dosHeader.E_crlc)
	fmt.Fprintf(writer, "%s\t%x\n", "e_cparhdr", dosHeader.E_cparhdr)
	fmt.Fprintf(writer, "%s\t%x\n", "e_minalloc", dosHeader.E_minalloc)
	fmt.Fprintf(writer, "%s\t%x\n", "e_maxalloc", dosHeader.E_maxalloc)
	fmt.Fprintf(writer, "%s\t%x\n", "e_ss", dosHeader.E_ss)
	fmt.Fprintf(writer, "%s\t%x\n", "e_sp", dosHeader.E_sp)
	fmt.Fprintf(writer, "%s\t%x\n", "e_csum", dosHeader.E_csum)
	fmt.Fprintf(writer, "%s\t%x\n", "e_ip", dosHeader.E_ip)
	fmt.Fprintf(writer, "%s\t%x\n", "e_cs", dosHeader.E_cs)
	fmt.Fprintf(writer, "%s\t%x\n", "e_lfarlc", dosHeader.E_lfarlc)
	fmt.Fprintf(writer, "%s\t%x\n", "e_ovno", dosHeader.E_ovno)
	fmt.Fprintf(writer, "%s\t%02x\n", "e_res", dosHeader.E_res[:])
	fmt.Fprintf(writer, "%s\t%x\n", "e_oemid", dosHeader.E_oemid)
	fmt.Fprintf(writer, "%s\t%x\n", "e_oeminfo", dosHeader.E_oeminfo)
	fmt.Fprintf(writer, "%s\t%02x\n", "e_res2", dosHeader.E_res2[:])
	fmt.Fprintf(writer, "%s\t%x\n", "e_lfanew", dosHeader.E_lfanew)
	fmt.Fprintf(writer, "\n")
	writer.Flush()
}

func printSectionHeader(sectionHeader pe.IMAGE_SECTION_HEADER) {
	name := pe.NullString(sectionHeader.Name[:])
	fmt.Println("[+] section header")
	writer := tabwriter.NewWriter(os.Stdout, 1, 1, 5, ' ', 0)
	fmt.Fprintf(writer, "%s\t%s\n", "Name", name)
	fmt.Fprintf(writer, "%s\t%x\n", "Misc", sectionHeader.Misc)
	fmt.Fprintf(writer, "%s\t%x\n", "VirtualAddress", sectionHeader.VirtualAddress)
	fmt.Fprintf(writer, "%s\t%x\n", "SizeOfRawData", sectionHeader.SizeOfRawData)
	fmt.Fprintf(writer, "%s\t%x\n", "PointerToRawData", sectionHeader.PointerToRawData)
	fmt.Fprintf(writer, "%s\t%x\n", "PointerToRelocations", sectionHeader.PointerToRelocations)
	fmt.Fprintf(writer, "%s\t%x\n", "PointerToLinenumbers", sectionHeader.PointerToLinenumbers)
	fmt.Fprintf(writer, "%s\t%x\n", "NumberOfRelocations", sectionHeader.NumberOfRelocations)
	fmt.Fprintf(writer, "%s\t%x\n", "NumberOfLineNumbers", sectionHeader.NumberOfLinenumbers)
	fmt.Fprintf(writer, "%s\t%x\n", "Characteristics", sectionHeader.Characteristics)
	fmt.Fprintf(writer, "\n")
	writer.Flush()
}

func printExportDirectory(pebytes []byte, exportDir pe.IMAGE_EXPORT_DIRECTORY) {
	fmt.Print("[+] Export Directory\n")
	name := pe.OffsetToString(pebytes, pe.RvaToOffset(pebytes, exportDir.Name))
	writer := tabwriter.NewWriter(os.Stdout, 1, 1, 5, ' ', 0)
	fmt.Fprintf(writer, "%s\t%x\n", "Characteristics", exportDir.Characteristics)
	fmt.Fprintf(writer, "%s\t%x\n", "TimeDateStamp", exportDir.TimeDateStamp)
	fmt.Fprintf(writer, "%s\t%x\n", "MajorVersion", exportDir.MajorVersion)
	fmt.Fprintf(writer, "%s\t%x\n", "MinorVersion", exportDir.MinorVersion)
	fmt.Fprintf(writer, "%s\t%s\n", "Name", name)
	fmt.Fprintf(writer, "%s\t%x\n", "Base", exportDir.Base)
	fmt.Fprintf(writer, "%s\t%x\n", "NumberOfFunctions", exportDir.NumberOfFunctions)
	fmt.Fprintf(writer, "%s\t%x\n", "NumberOfNames", exportDir.NumberOfNames)
	fmt.Fprintf(writer, "%s\t%x\n", "AddressOfFunctions", exportDir.AddressOfFunctions)
	fmt.Fprintf(writer, "%s\t%x\n", "AddressOfNames", exportDir.AddressOfNames)
	fmt.Fprintf(writer, "%s\t%x\n", "AddressOfNameOrdinals", exportDir.AddressOfNameOrdinals)
	fmt.Fprintf(writer, "\n")
	writer.Flush()
}

func printTLSDirectory(size uint16, pebytes []byte, directory pe.IMAGE_DATA_DIRECTORY) {
	writer := tabwriter.NewWriter(os.Stdout, 1, 1, 5, ' ', 0)
	fmt.Fprintf(writer, "[+] TLS\n")
	if size == 0xe0 {
		imageTLSDirectory := (*pe.IMAGE_TLS_DIRECTORY32)(unsafe.Pointer(&pebytes[pe.RvaToOffset(pebytes, directory.VirtualAddress)]))
		fmt.Fprintf(writer, "%s\t%x\n", "StartAddressOfRawData", imageTLSDirectory.StartAddressOfRawData)
		fmt.Fprintf(writer, "%s\t%x\n", "EndAddressOfRawData", imageTLSDirectory.EndAddressOfRawData)
		fmt.Fprintf(writer, "%s\t%x\n", "AddressOfIndex", imageTLSDirectory.AddressOfIndex)
		fmt.Fprintf(writer, "%s\t%x\n", "AddressOfCallBacks", imageTLSDirectory.AddressOfCallBacks)
		fmt.Fprintf(writer, "%s\t%x\n", "SizeOfZeroFill", imageTLSDirectory.SizeOfZeroFill)
		fmt.Fprintf(writer, "%s\t%x\n", "Characteristics", imageTLSDirectory.Characteristics)
		fmt.Fprintf(writer, "\nTLS Callbacks:\n")
		fmt.Fprintf(writer, "%s\t%s\n", "VirtualAddress", "Offset")

		offset := pe.VaToOffset(pebytes, imageTLSDirectory.AddressOfCallBacks)
		for {
			callback_va := binary.LittleEndian.Uint32(pebytes[offset : offset+4])
			if callback_va == 0 {
				break
			}
			fmt.Fprintf(writer, "%x\t%x\n", callback_va, offset)
			offset += 4
		}
	} else if size == 0xf0 {
		imageTLSDirectory := (*pe.IMAGE_TLS_DIRECTORY64)(unsafe.Pointer(&pebytes[pe.RvaToOffset(pebytes, directory.VirtualAddress)]))
		fmt.Fprintf(writer, "%s\t%x\n", "StartAddressOfRawData", imageTLSDirectory.StartAddressOfRawData)
		fmt.Fprintf(writer, "%s\t%x\n", "EndAddressOfRawData", imageTLSDirectory.EndAddressOfRawData)
		fmt.Fprintf(writer, "%s\t%x\n", "AddressOfIndex", imageTLSDirectory.AddressOfIndex)
		fmt.Fprintf(writer, "%s\t%x\n", "AddressOfCallBacks", imageTLSDirectory.AddressOfCallBacks)
		fmt.Fprintf(writer, "%s\t%x\n", "SizeOfZeroFill", imageTLSDirectory.SizeOfZeroFill)
		fmt.Fprintf(writer, "%s\t%x\n", "Characteristics", imageTLSDirectory.Characteristics)
		fmt.Fprintf(writer, "\nTLS Callbacks:\n")
		fmt.Fprintf(writer, "%s\t%s\n", "VirtualAddress", "Offset")

		offset := pe.VaToOffset64(pebytes, imageTLSDirectory.AddressOfCallBacks)
		for {
			callback_va := binary.LittleEndian.Uint32(pebytes[offset : offset+4])
			if callback_va == 0 {
				break
			}
			fmt.Fprintf(writer, "%x\t%x\n", callback_va, offset)
			offset += 4
		}
	}

	fmt.Fprintf(writer, "\n")
	writer.Flush()
}

func printIATDirectory(size uint16, pebytes []byte, directory pe.IMAGE_DATA_DIRECTORY) {
	writer := tabwriter.NewWriter(os.Stdout, 1, 1, 5, ' ', 0)
	fmt.Fprintf(writer, "[+] IAT\n")
	fmt.Fprintf(writer, "Name\tThunk\tHint\n")

	if size == 0xe0 {
		rva := pe.RvaToOffset(pebytes, directory.VirtualAddress)
		start_rva := rva

		for start_rva+directory.Size > rva {
			thunk := (*pe.IMAGE_THUNK_DATA32)(unsafe.Pointer(&pebytes[rva]))
			if thunk.U1 != 0 {
				imp_by_name := (*pe.IMAGE_IMPORT_BY_NAME)(unsafe.Pointer(&pebytes[pe.RvaToOffset(pebytes, thunk.U1)]))
				name := pe.PtrToString(uintptr(unsafe.Pointer(&imp_by_name.Name[0])))
				fmt.Fprintf(writer, "%s\t%x\t%x\n", name, thunk.U1, imp_by_name.Hint)
			} else {
				fmt.Fprintf(writer, "\t\t\n")
			}
			rva += 4
		}
	} else if size == 0xf0 {
		rva := pe.RvaToOffset(pebytes, directory.VirtualAddress)
		start_rva := rva

		for start_rva+directory.Size > rva {
			thunk := (*pe.IMAGE_THUNK_DATA64)(unsafe.Pointer(&pebytes[rva]))
			if thunk.U1 != 0 {
				imp_by_name := (*pe.IMAGE_IMPORT_BY_NAME)(unsafe.Pointer(&pebytes[pe.RvaToOffset64(pebytes, thunk.U1)]))
				name := pe.PtrToString(uintptr(unsafe.Pointer(&imp_by_name.Name[0])))
				fmt.Fprintf(writer, "%s\t%x\t%x\n", name, thunk.U1, imp_by_name.Hint)
			} else {
				fmt.Fprintf(writer, "\t\t\n")
			}
			rva += 8
		}
	}
	fmt.Fprintf(writer, "\n")
	writer.Flush()
}

func printImportDirectory(size uint16, pebytes []byte, importDir pe.IMAGE_DATA_DIRECTORY) {
	fmt.Println(size)
	writer := tabwriter.NewWriter(os.Stdout, 1, 1, 5, ' ', 0)
	fmt.Fprintf(writer, "[+] Import Directory\n")
	for importDescriptorOffset := 0; ; importDescriptorOffset++ {
		offset := pe.RvaToOffset(pebytes, importDir.VirtualAddress+uint32(unsafe.Sizeof(pe.IMAGE_IMPORT_DESCRIPTOR{})*uintptr(importDescriptorOffset)))
		importDesc := pe.FillImportDescriptor(pebytes, offset)

		if importDesc.DUMMYUNIONNAME == 0 && importDesc.FirstThunk == 0 && importDesc.ForwarderChain == 0 && importDesc.Name == 0 && importDesc.TimeDatestamp == 0 {
			break
		}

		name := pe.OffsetToString(pebytes, pe.RvaToOffset(pebytes, importDesc.Name))
		fmt.Fprintf(writer, "[+] Imported DLL: %s\t\n", name)
		fmt.Fprintf(writer, "%s\t%x\n", "DUMMYUNIONNAME", importDesc.DUMMYUNIONNAME)
		fmt.Fprintf(writer, "%s\t%x\n", "TimeDatestamp", importDesc.TimeDatestamp)
		fmt.Fprintf(writer, "%s\t%x\n", "ForwarderChain", importDesc.ForwarderChain)
		fmt.Fprintf(writer, "%s\t%s\n", "Name", name)
		fmt.Fprintf(writer, "%s\t%x\n", "FirstThunk", importDesc.FirstThunk)
		fmt.Fprintf(writer, "\t\n")

		fmt.Fprintf(writer, "%s\t%s\n", "Import", "Hint")
		var thunkDataOffset uint32 = 0
		for {
			iatArr := pe.FillThunkData32(pebytes, pe.RvaToOffset(pebytes, importDesc.FirstThunk+(uint32(unsafe.Sizeof(pe.IMAGE_THUNK_DATA32{}))*thunkDataOffset)))
			if iatArr.U1 == 0 {
				break
			}
			importName := pe.FillImportByName(pebytes, pe.RvaToOffset(pebytes, iatArr.U1))

			name := pe.PtrToString(uintptr(unsafe.Pointer(&importName.Name[0])))

			fmt.Fprintf(writer, "%s\t%x\n", name, importName.Hint)
			thunkDataOffset++
		}

	}

	fmt.Fprintf(writer, "\n")
	writer.Flush()
}

func printExports(pebytes []byte, directory pe.IMAGE_DATA_DIRECTORY, export pe.IMAGE_EXPORT_DIRECTORY, ordinals []uint16, names []string, addressOfFunctions []uint32) {
	var i uint32 = 0
	writer := tabwriter.NewWriter(os.Stdout, 1, 1, 5, ' ', 0)
	for {

		if i > export.NumberOfFunctions-1 {
			break
		}
		if i < export.NumberOfNames {
			if pe.IsForwarded(addressOfFunctions[ordinals[i]-uint16(export.Base)], directory.VirtualAddress, directory.Size) {
				fmt.Fprintf(writer, "%s\t%x\t%x -> %s\n", names[i], ordinals[i], addressOfFunctions[ordinals[i]-uint16(export.Base)], pe.OffsetToString(pebytes, pe.RvaToOffset(pebytes, addressOfFunctions[ordinals[i]-uint16(export.Base)])))
			} else {
				fmt.Fprintf(writer, "%s\t%x\t%x\n", names[i], ordinals[i], addressOfFunctions[ordinals[i]-uint16(export.Base)])
			}
		} else {
			if pe.IsForwarded(addressOfFunctions[ordinals[i]-uint16(export.Base)], directory.VirtualAddress, directory.Size) {
				fmt.Fprintf(writer, "%s\t%x\t%x -> %s\n", "", ordinals[i], addressOfFunctions[ordinals[i]-uint16(export.Base)], pe.OffsetToString(pebytes, pe.RvaToOffset(pebytes, addressOfFunctions[ordinals[i]-uint16(export.Base)])))
			} else {
				fmt.Fprintf(writer, "%s\t%x\t%x\n", "", ordinals[i], addressOfFunctions[ordinals[i]-uint16(export.Base)])
			}
		}
		i++
	}
	fmt.Fprintf(writer, "\n")
	writer.Flush()
}

func printRelocationDirectory(pebytes []byte, directory pe.IMAGE_DATA_DIRECTORY) {
	var offset uint32
	writer := tabwriter.NewWriter(os.Stdout, 1, 1, 5, ' ', 0)
	fmt.Fprintf(writer, "[+] Relocation Directory\n\n")
	for {
		baserelocation := (*pe.IMAGE_BASE_RELOCATION)(unsafe.Pointer(&pebytes[pe.RvaToOffset(pebytes, directory.VirtualAddress)+offset]))
		if baserelocation.VirtualAddress == 0 || baserelocation.SizeOfBlock == 0 {
			break
		}

		fmt.Fprintf(writer, "[+] Relocation Block\n")
		fmt.Fprintf(writer, "%s\t%x\n", "SizeOfBlock", baserelocation.SizeOfBlock)
		fmt.Fprintf(writer, "%s\t%x\n", "VirtualAddress", baserelocation.VirtualAddress)
		fmt.Fprintf(writer, "%s\t%x\n", "Entries", (baserelocation.SizeOfBlock-8)/2)
		fmt.Fprintf(writer, "\n")
		fmt.Fprintf(writer, "%s\t%s\t%s\n", "Value", "Offset from page", "Flag")
		var entryOffset uint32
		for i := 0; i < int((baserelocation.SizeOfBlock-8)/2); i++ {
			value := *(*uint16)(unsafe.Pointer(&pebytes[pe.RvaToOffset(pebytes, directory.VirtualAddress)+offset+8+entryOffset]))
			fmt.Fprintf(writer, "%x\t%x\t%x\n", value, (value^0xF000)&value, ((value^0x0FFF)&value)>>12)
			entryOffset += 2
		}
		fmt.Fprintf(writer, "\n")
		offset += baserelocation.SizeOfBlock
	}
	fmt.Fprintf(writer, "\n")
	writer.Flush()
}

func printDelayedImportDirectory(pebytes []byte, directory pe.IMAGE_DATA_DIRECTORY) {
	writer := tabwriter.NewWriter(os.Stdout, 1, 1, 5, ' ', 0)
	fmt.Fprintf(writer, "[+] Delayed imports")
	var i uint32
	for i = 0; ; i += uint32(unsafe.Sizeof(pe.IMAGE_DELAYLOAD_DESCRIPTOR{})) {
		if pebytes[int(pe.RvaToOffset(pebytes, directory.VirtualAddress)+i)] == 0 {
			break
		}

		delayLoadDescriptor := (*pe.IMAGE_DELAYLOAD_DESCRIPTOR)(unsafe.Pointer(&pebytes[pe.RvaToOffset(pebytes, directory.VirtualAddress)+i]))
		fmt.Fprintf(writer, "%s\t%x\n", "Attributes", delayLoadDescriptor.Attributes)
		fmt.Fprintf(writer, "%s\t%s\n", "DllName", pe.OffsetToString(pebytes, pe.RvaToOffset(pebytes, uint32(delayLoadDescriptor.DllNameRVA))))
		fmt.Fprintf(writer, "%s\t%x\n", "ModuleHandleRVA", delayLoadDescriptor.ModuleHandleRVA)
		fmt.Fprintf(writer, "%s\t%x\n", "ImportAddressTableRVA", delayLoadDescriptor.ImportAddressTableRVA)
		fmt.Fprintf(writer, "%s\t%x\n", "ImportNameTableRVA", delayLoadDescriptor.ImportNameTableRVA)
		fmt.Fprintf(writer, "%s\t%x\n", "BoundImportAddresstableRVA", delayLoadDescriptor.BoundImportAddressTableRVA)
		fmt.Fprintf(writer, "%s\t%x\n", "UnloadInformationTableRVA", delayLoadDescriptor.UnloadInformationTableRVA)

		fmt.Fprintf(writer, "\n[+] Imports\t\n")
		fmt.Fprintf(writer, "%s\t%s\n", "Import", "Hint")
		for j := 0; ; j += 4 {
			importNameRva := pe.RvaToOffset(pebytes, delayLoadDescriptor.ImportNameTableRVA+uint32(j))
			importnameOffset := pe.RvaToOffset(pebytes, binary.LittleEndian.Uint32(pebytes[importNameRva:]))
			if importnameOffset == 0 {
				break
			}

			t := pe.FillImportByName(pebytes, importnameOffset)
			name := pe.PtrToString(uintptr(unsafe.Pointer(&t.Name[0])))
			fmt.Fprintf(writer, "%s\t%x\n", name, t.Hint)
		}

		fmt.Fprintf(writer, "\n[+] IAT\t\n")
		for j := 0; ; j += 4 {
			addressRva := pe.RvaToOffset(pebytes, delayLoadDescriptor.ImportAddressTableRVA+uint32(j))
			if binary.LittleEndian.Uint32(pebytes[addressRva:]) == 0 {
				break
			}
			fmt.Fprintf(writer, "%x\t\n", binary.LittleEndian.Uint32(pebytes[addressRva:]))
		}
	}

	fmt.Fprintf(writer, "\n")
	writer.Flush()
}

func printExceptionDirectory(pebytes []byte, directory pe.IMAGE_DATA_DIRECTORY) {
	var offset uint32
	for {
		exceptiontable := (*pe.IMAGE_RUNTIME_FUNCTION_ENTRY)(unsafe.Pointer(&pebytes[pe.RvaToOffset(pebytes, directory.VirtualAddress)+offset]))
		if exceptiontable.BeginAddress == 0 || exceptiontable.EndAddress == 0 || exceptiontable.UnWindInfoAddress == 0 {
			break
		}
		fmt.Printf("%x %x %x\n", exceptiontable.BeginAddress, exceptiontable.EndAddress, exceptiontable.UnWindInfoAddress)
		offset += uint32(unsafe.Sizeof(pe.IMAGE_RUNTIME_FUNCTION_ENTRY{}))
	}

	os.Exit(0)
}

func printResourceDirectory(pebytes []byte, directory pe.IMAGE_DATA_DIRECTORY) {
	relocationDirectory := (*pe.IMAGE_RESOURCE_DIRECTORY)(unsafe.Pointer(&pebytes[pe.RvaToOffset(pebytes, directory.VirtualAddress)]))
	writer := tabwriter.NewWriter(os.Stdout, 1, 1, 5, ' ', 0)
	fmt.Fprintf(writer, "[+] Relocation Directory\n")
	fmt.Fprintf(writer, "%s\t%x\n", "Characteristics", relocationDirectory.Charateristics)
	fmt.Fprintf(writer, "%s\t%x\n", "TimeDateStamp", relocationDirectory.TimeDateStamp)
	fmt.Fprintf(writer, "%s\t%x\n", "MajorVersion", relocationDirectory.MajorVersion)
	fmt.Fprintf(writer, "%s\t%x\n", "MinorVersion", relocationDirectory.MinorVersion)
	fmt.Fprintf(writer, "%s\t%x\n", "NumberOfNamedEntires", relocationDirectory.NumberOfNamedEntries)
	fmt.Fprintf(writer, "%s\t%x\n", "NumberOfIdEntries", relocationDirectory.NumberOfIdEntries)
	fmt.Fprintf(writer, "\n")
	writer.Flush()
}
