//go:build windows
// +build windows

package main

import (
	"fmt"
	"log"
	"os"
	pe "pe/pkg"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// https://learn.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants
// https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-entry-point-function
const PAGE_EXECUTE = 0x10
const PAGE_READONLY = 0x02
const PAGE_EXECUTE_READ = 0x20
const PAGE_EXECUTE_READWRITE = 0x40
const PAGE_READWRITE = 0x04

const MEM_RESERVE = 0x00002000

const MEM_COMMIT = 0x00001000

var (
	Kernel32dll = syscall.NewLazyDLL("kernel32.dll")
	NTDLL       = syscall.NewLazyDLL("ntdll.dll")

	VirtualAlloc   = Kernel32dll.NewProc("VirtualAlloc")
	RtlMoveMemory  = Kernel32dll.NewProc("RtlMoveMemory")
	VirtualProtect = Kernel32dll.NewProc("VirtualProtect")
	LoadLibraryW   = Kernel32dll.NewProc("LoadLibraryW")
	GetProcAddress = Kernel32dll.NewProc("GetProcAddress")
	TlsAlloc       = Kernel32dll.NewProc("TlsAlloc")
	TlsSetValue    = Kernel32dll.NewProc("TlsSetValue")

	LdrpCallInitRoutine = NTDLL.NewProc("LdrpCallInitRoutine")
)

func main() {

	pebytes, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println("[-]", err.Error())
		return
	}
	dosHeader := pe.FillDosHeader(pebytes)
	fileHeader := pe.FillFileHeader(pebytes, dosHeader.E_lfanew+4)

	var image_data_directory [16]pe.IMAGE_DATA_DIRECTORY
	var dynamicImageBase uintptr
	var imageBase uintptr
	var entryPoint uintptr
	var sizeOfHeaders uint32

	if fileHeader.SizeOfOptionalHeader == uint16(unsafe.Sizeof(pe.IMAGE_OPTIONAL_HEADER{})) {
		optionHeader := pe.FillOptionalHeader(pebytes, dosHeader.E_lfanew+4+0x14)

		imageBase = uintptr(optionHeader.ImageBase)

		entryPoint = uintptr(optionHeader.AddressOfEntryPoint)

		dynamicImageBase, _, err = VirtualAlloc.Call(0, uintptr(optionHeader.SizeOfImage), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)

		sizeOfHeaders = optionHeader.SizeOfHeaders

		image_data_directory = optionHeader.DataDirectory

	} else if fileHeader.SizeOfOptionalHeader == 0xF0 {
		optionHeader64 := pe.FillOptionalHeader64(pebytes, dosHeader.E_lfanew+4+0x14)

		imageBase = uintptr(optionHeader64.ImageBase)

		entryPoint = uintptr(optionHeader64.AddressOfEntryPoint)

		dynamicImageBase, _, err = VirtualAlloc.Call(0, uintptr(optionHeader64.SizeOfImage), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)

		sizeOfHeaders = optionHeader64.SizeOfHeaders

		image_data_directory = optionHeader64.DataDirectory

	} else {
		fmt.Println("[-] invalid fileheader size")
		return
	}

	if dynamicImageBase == 0 {
		log.Fatal(err)
	} else {
		fmt.Printf("[+] image base at %x\n", dynamicImageBase)
	}

	fmt.Printf("[+] size of headers %x\n", sizeOfHeaders)

	RtlMoveMemory.Call(dynamicImageBase, uintptr(unsafe.Pointer(&pebytes[0])), uintptr(sizeOfHeaders))

	var sectionOffset int32 = dosHeader.E_lfanew + 4 + 0x14 + int32(fileHeader.SizeOfOptionalHeader)
	for range fileHeader.NumberOfSections {

		sectionheader := pe.FillSectionHeader(pebytes, sectionOffset)

		memaddr := dynamicImageBase + uintptr(sectionheader.VirtualAddress)

		sectionbytes := make([]byte, sectionheader.SizeOfRawData)

		copy(sectionbytes, pebytes[sectionheader.PointerToRawData:sectionheader.PointerToRawData+sectionheader.SizeOfRawData])

		RtlMoveMemory.Call(memaddr,
			uintptr(unsafe.Pointer(&sectionbytes[0])),
			uintptr(sectionheader.SizeOfRawData))

		fmt.Printf("[+] copied %x bytes from section %s to %x\n", sectionheader.SizeOfRawData, pe.NullString(sectionheader.Name[:]), memaddr)

		var oldProc uintptr

		if (sectionheader.Characteristics & (pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_WRITE | pe.IMAGE_SCN_MEM_EXECUTE)) == (pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_WRITE | pe.IMAGE_SCN_MEM_EXECUTE) {
			VirtualProtect.Call(memaddr, uintptr(sectionheader.SizeOfRawData), PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProc)))
			fmt.Printf("[+] %x marked rwx\n", memaddr)
		} else if (sectionheader.Characteristics & (pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_WRITE)) == (pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_WRITE) {
			VirtualProtect.Call(memaddr, uintptr(sectionheader.SizeOfRawData), PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProc)))
			fmt.Printf("[+] %x marked rw\n", memaddr)
		} else if (sectionheader.Characteristics & pe.IMAGE_SCN_MEM_READ) == pe.IMAGE_SCN_MEM_READ {
			VirtualProtect.Call(memaddr, uintptr(sectionheader.SizeOfRawData), PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProc)))
			fmt.Printf("[+] %x marked r\n", memaddr)
		}
		sectionOffset += int32(unsafe.Sizeof(pe.IMAGE_SECTION_HEADER{}))
	}

	//fix relocations
	relocDir := image_data_directory[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC]
	if relocDir.Size != 0 {
		fixRelocations(relocDir, dynamicImageBase, imageBase)
	}
	//fix iat
	importDir := image_data_directory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
	if importDir.Size != 0 {
		fixImports(importDir, dynamicImageBase)
	}

	//call tls functions

	tlsDir := image_data_directory[pe.IMAGE_DIRECTORY_ENTRY_TLS]
	if tlsDir.Size != 0 {
		runTLS(tlsDir, dynamicImageBase, entryPoint)
	}

	fmt.Println(image_data_directory)
}

func runTLS(directory pe.IMAGE_DATA_DIRECTORY, memimagebase uintptr, entryPoint uintptr) {
	tlsDirectoryAddress := memimagebase + uintptr(directory.VirtualAddress)

	fmt.Printf("[+] tls directory at %x\n", tlsDirectoryAddress)

	imageTLSDirectory := (*pe.IMAGE_TLS_DIRECTORY32)(unsafe.Pointer(tlsDirectoryAddress))
	fmt.Printf("AddressOfCallBacks=%x AddressOfIndex=%x Characteristics=%x EndAddressOfRawData=%x SizeOfZeroFill=%x StartAddressOfRawData=%x\n", imageTLSDirectory.AddressOfCallBacks,
		imageTLSDirectory.AddressOfIndex,
		imageTLSDirectory.Characteristics,
		imageTLSDirectory.EndAddressOfRawData,
		imageTLSDirectory.SizeOfZeroFill,
		imageTLSDirectory.StartAddressOfRawData)

	sizeOfTLSData := uintptr(imageTLSDirectory.EndAddressOfRawData - imageTLSDirectory.StartAddressOfRawData)

	fmt.Printf("[+] size of tls data %x\n", sizeOfTLSData)

	tlsAddress, _, err := VirtualAlloc.Call(0, sizeOfTLSData, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	if tlsAddress == 0 {
		log.Fatal(err)
	}

	tlsData := make([]byte, sizeOfTLSData)
	pe.ReadBytesFromPtr(uintptr(imageTLSDirectory.StartAddressOfRawData), uint32(sizeOfTLSData))
	copy(tlsData, pe.ReadBytesFromPtr(uintptr(imageTLSDirectory.StartAddressOfRawData), uint32(sizeOfTLSData)))

	RtlMoveMemory.Call(tlsAddress,
		uintptr(unsafe.Pointer(&tlsData[0])),
		sizeOfTLSData)

	tls_index, _, err := TlsAlloc.Call()
	if tls_index == uintptr(pe.TLS_OUT_OF_INDEXES) {
		log.Fatal(err)
	}

	if imageTLSDirectory.AddressOfIndex != 0 {
		tlsIndexAddress := uintptr(imageTLSDirectory.AddressOfIndex) + memimagebase

		fmt.Printf("[+] tls index %x at %x\n", tls_index, tlsIndexAddress)

		*(*uint32)(unsafe.Pointer(&tlsIndexAddress)) = uint32(tls_index)
	}

	if sizeOfTLSData > 0 {
		r1, _, err := TlsSetValue.Call(tls_index, uintptr(imageTLSDirectory.StartAddressOfRawData))
		if r1 == 0 {
			log.Fatal(err)
		}
	}

	if imageTLSDirectory.AddressOfCallBacks != 0 {

		callbackoffset := uintptr(0)
		for {
			callbackAddress := *(*uint32)(unsafe.Pointer(uintptr(imageTLSDirectory.AddressOfCallBacks + uint32(callbackoffset))))
			if callbackAddress == 0 {
				break
			}

			fmt.Printf("[+] callback address %x\n", callbackAddress)
			fmt.Printf("[+] entry point %x\n", memimagebase+uintptr(entryPoint))

			// execute call back here

			callbackoffset += 4
		}
	}

}

func fixImports(directory pe.IMAGE_DATA_DIRECTORY, memimagebase uintptr) {
	var imageDescriptorOffset uintptr
	for {
		imageDescriptorAddress := uintptr(memimagebase + uintptr(directory.VirtualAddress) + imageDescriptorOffset)
		imageDescriptor := (*pe.IMAGE_IMPORT_DESCRIPTOR)(unsafe.Pointer(imageDescriptorAddress))

		if imageDescriptor.Name == 0 {
			break
		}

		modulename := pe.PtrToString(memimagebase + uintptr(imageDescriptor.Name))
		fmt.Println(imageDescriptor)

		moduleAddress, _, _ := LoadLibraryW.Call(uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(modulename))))
		fmt.Printf("[+] %s = %x\n", modulename, moduleAddress)
		fmt.Printf("%x %x %x %x %x\n",
			imageDescriptor.DUMMYUNIONNAME,
			imageDescriptor.FirstThunk,
			imageDescriptor.ForwarderChain,
			imageDescriptor.Name,
			imageDescriptor.TimeDatestamp)

		var iatArrOffset uintptr
		for {
			imageThunkAddress := uintptr(memimagebase + uintptr(imageDescriptor.FirstThunk) + iatArrOffset)

			thunk := (*pe.IMAGE_THUNK_DATA32)(unsafe.Pointer(imageThunkAddress))
			if thunk.U1 != 0 {
				importByNameOffset := uintptr(memimagebase + uintptr(thunk.U1))
				imp_by_name := (*pe.IMAGE_IMPORT_BY_NAME)(unsafe.Pointer(importByNameOffset))
				name := pe.PtrToString(uintptr(unsafe.Pointer(&imp_by_name.Name[0])))

				functionAddress, _, _ := GetProcAddress.Call(moduleAddress, uintptr(unsafe.Pointer(&imp_by_name.Name[0])))

				oldFunctionAddress := *(*uint32)(unsafe.Pointer(importByNameOffset))
				fmt.Printf("%s %x -> %x\n", name, oldFunctionAddress, functionAddress)

				*(*uint32)(unsafe.Pointer(importByNameOffset)) = uint32(functionAddress)

			} else {
				break
			}

			iatArrOffset += 4
		}

		imageDescriptorOffset += 0x14
	}
}

func fixRelocations(directory pe.IMAGE_DATA_DIRECTORY, memimagebase uintptr, diskimagebase uintptr) {
	var offset uint32

	for {
		fmt.Printf("[+] relocation directory: VA=%x\n", directory.VirtualAddress)

		baserelocationaddress := uintptr(memimagebase+uintptr(directory.VirtualAddress)) + uintptr(offset)

		baserelocation := *(*pe.IMAGE_BASE_RELOCATION)(unsafe.Pointer(baserelocationaddress))

		fmt.Printf("[+] base relocation table: VA=%x SIZE=%x\n", baserelocation.VirtualAddress, baserelocation.SizeOfBlock)

		if baserelocation.VirtualAddress == 0 || baserelocation.SizeOfBlock == 0 {
			break
		}

		var entryOffset uint32

		fmt.Printf("[+] reading relocation at %x\n", baserelocationaddress+8+uintptr(entryOffset))

		for range (baserelocation.SizeOfBlock - 8) / 2 {
			value := *(*uint16)(unsafe.Pointer(baserelocationaddress + 8 + uintptr(entryOffset)))

			addressoffset := (value ^ 0xF000) & value

			//bitfield := ((value ^ 0x0FFF) & value) >> 12

			//fmt.Printf("%x %x %x\n", value, bitfield, addressoffset)

			relocationAddressOffset := memimagebase + uintptr(baserelocation.VirtualAddress) + uintptr(addressoffset)

			address := *(*uint32)(unsafe.Pointer(relocationAddressOffset))

			newaddress := (address - uint32(diskimagebase)) + uint32(memimagebase)

			*(*uint32)(unsafe.Pointer(relocationAddressOffset)) = newaddress

			fmt.Printf("relocated %x -> %x\n", address, *(*uint32)(unsafe.Pointer(relocationAddressOffset)))

			entryOffset += 2
		}

		offset += baserelocation.SizeOfBlock

	}
}
