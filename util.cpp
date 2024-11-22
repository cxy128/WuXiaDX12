#include <sstream>
#include "util.h"

bool InitSystemRoutineAddress() {

	auto Handle = GetModuleHandleA("ntdll.dll");
	if (!Handle) {
		return false;
	}

	ZwQuerySystemInformation = (fnZwQuerySystemInformation)GetProcAddress(Handle, "ZwQuerySystemInformation");
	if (!ZwQuerySystemInformation) {
		return false;
	}

	ZwAllocateVirtualMemory = (fnZwAllocateVirtualMemory)GetProcAddress(Handle, "ZwAllocateVirtualMemory");
	if (!ZwAllocateVirtualMemory) {
		return false;
	}

	ZwFreeVirtualMemory = (fnZwFreeVirtualMemory)GetProcAddress(Handle, "ZwFreeVirtualMemory");
	if (!ZwFreeVirtualMemory) {
		return false;
	}

	ZwReadVirtualMemory = (fnZwReadVirtualMemory)GetProcAddress(Handle, "ZwReadVirtualMemory");
	if (!ZwReadVirtualMemory) {
		return false;
	}

	ZwWriteVirtualMemory = (fnZwWriteVirtualMemory)GetProcAddress(Handle, "ZwWriteVirtualMemory");
	if (!ZwWriteVirtualMemory) {
		return false;
	}

	ZwProtectVirtualMemory = (fnZwProtectVirtualMemory)GetProcAddress(Handle, "ZwProtectVirtualMemory");
	if (!ZwProtectVirtualMemory) {
		return false;
	}

	ZwGetNextThread = (fnZwGetNextThread)GetProcAddress(Handle, "ZwGetNextThread");
	if (!ZwGetNextThread) {
		return false;
	}

	ZwQueueApcThreadEx = (fnZwQueueApcThreadEx)GetProcAddress(Handle, "ZwQueueApcThreadEx");
	if (!ZwQueueApcThreadEx) {
		return false;
	}

	return true;
}

bool InitMappingParameter(MappingParameter* Parameter, void* ImageBase) {

	auto Kernel32 = GetModuleHandleW(L"Kernel32.dll");
	if (!Kernel32) {
		return false;
	}

	auto ntdll = GetModuleHandleW(L"ntdll.dll");
	if (!ntdll) {
		return false;
	}

	Parameter->IsExecution = false;
	Parameter->IsStartDllMain = false;

	Parameter->ImageBase = reinterpret_cast<unsigned __int64>(ImageBase);

	Parameter->fLoadLibraryA = reinterpret_cast<fnLoadLibraryA>(GetProcAddress(Kernel32, "LoadLibraryA"));
	Parameter->fGetProcAddress = reinterpret_cast<fnGetProcAddress>(GetProcAddress(Kernel32, "GetProcAddress"));
	Parameter->fRtlAddFunctionTable = reinterpret_cast<fnRtlAddFunctionTable>(GetProcAddress(Kernel32, "RtlAddFunctionTable"));

	if (!Parameter->fLoadLibraryA || !Parameter->fGetProcAddress || !Parameter->fRtlAddFunctionTable) {
		return false;
	}

	Parameter->fVirtualAlloc = reinterpret_cast<fnVirtualAlloc>(GetProcAddress(Kernel32, "VirtualAlloc"));
	Parameter->fRtlCopyMemory = reinterpret_cast<fnRtlCopyMemory>(GetProcAddress(ntdll, "RtlCopyMemory"));
	Parameter->fGetThreadContext = reinterpret_cast<fnGetThreadContext>(GetProcAddress(Kernel32, "GetThreadContext"));
	Parameter->fSetThreadContext = reinterpret_cast<fnSetThreadContext>(GetProcAddress(Kernel32, "SetThreadContext"));

	if (!Parameter->fVirtualAlloc || !Parameter->fRtlCopyMemory || !Parameter->fGetThreadContext || !Parameter->fSetThreadContext) {
		return false;
	}

	return true;
}

unsigned __int64 LoadModule(const wchar_t* FileName) {

	HANDLE FileHandle = nullptr;

	PVOID ModuleBuffer = nullptr;

	wchar_t DirectoryBuf[256] = L"";
	GetCurrentDirectoryW(256, DirectoryBuf);

	std::wstring DirectoryName(L"\\\\?\\");
	DirectoryName.append(DirectoryBuf).append(L"\\").append(FileName);

	for (;;) {

		FileHandle = CreateFile(DirectoryName.data(), FILE_ALL_ACCESS, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (!FileHandle || FileHandle == INVALID_HANDLE_VALUE) {
			break;
		}

		LARGE_INTEGER FileSize = {};
		if (!GetFileSizeEx(FileHandle, &FileSize)) {
			break;
		}

		unsigned __int64 ModuleSize = FileSize.QuadPart;
		auto Status = ZwAllocateVirtualMemory(GetCurrentProcess(), reinterpret_cast<void**>(&ModuleBuffer), 0, &ModuleSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (NT_ERROR(Status)) {
			break;
		}

		DWORD NumberOfBytesRead = 0;
		if (!ReadFile(FileHandle, ModuleBuffer, static_cast<unsigned __int32>(ModuleSize), &NumberOfBytesRead, nullptr)) {
			ZwFreeVirtualMemory(GetCurrentProcess(), reinterpret_cast<void**>(&ModuleBuffer), &ModuleSize, MEM_DECOMMIT);
			break;
		}

		if (!FlushFileBuffers(FileHandle)) {
			ZwFreeVirtualMemory(GetCurrentProcess(), reinterpret_cast<void**>(&ModuleBuffer), &ModuleSize, MEM_DECOMMIT);
			break;
		}

		break;
	}

	if (FileHandle) {
		CloseHandle(FileHandle);
	}

	return reinterpret_cast<unsigned __int64>(ModuleBuffer);
}

bool MappingModule(HANDLE ProcessHandle, unsigned __int64 ImageBase, void* f, unsigned __int64* call_f, unsigned __int64* ParameterAddress) {

	NTSTATUS Status = STATUS_SUCCESS;
	IMAGE_DOS_HEADER* DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(ImageBase);
	if (!DosHeader || DosHeader->e_magic != 0x5a4d) {
		return false;
	}

	IMAGE_NT_HEADERS* NtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(ImageBase + DosHeader->e_lfanew);
	IMAGE_FILE_HEADER* FileHeader = &NtHeader->FileHeader;
	IMAGE_OPTIONAL_HEADER* OptionalHeader = &NtHeader->OptionalHeader;

	unsigned __int64 ReturnSize = 0;

	unsigned char* ModuleAddress = nullptr;
	unsigned __int64 ModuleSize = OptionalHeader->SizeOfImage;

	unsigned char* ParameterAddressBuffer = nullptr;
	unsigned __int64 ParameterSize = PAGE_SIZE;

	unsigned char* fBuffer = nullptr;
	unsigned __int64 fSize = PAGE_SIZE;

	for (;;) {

		Status = ZwAllocateVirtualMemory(ProcessHandle, reinterpret_cast<void**>(&ModuleAddress), 0, &ModuleSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (NT_ERROR(Status)) {
			break;
		}

		Status = ZwWriteVirtualMemory(ProcessHandle, ModuleAddress, reinterpret_cast<void*>(ImageBase), PAGE_SIZE, &ReturnSize);
		if (NT_ERROR(Status)) {
			break;
		}

		MappingParameter Parameter = {};
		if (!InitMappingParameter(&Parameter, ModuleAddress)) {
			Status = STATUS_ACCESS_DENIED;
			break;
		}

		IMAGE_SECTION_HEADER* Sections = IMAGE_FIRST_SECTION(NtHeader);

		for (int i = 0; i < FileHeader->NumberOfSections; i++, Sections++) {

			if (Sections->SizeOfRawData) {

				Status = ZwWriteVirtualMemory(
					ProcessHandle,
					reinterpret_cast<void*>(ModuleAddress + Sections->VirtualAddress),
					reinterpret_cast<void*>(ImageBase + Sections->PointerToRawData),
					Sections->SizeOfRawData,
					&ReturnSize);

				if (NT_ERROR(Status)) {
					break;
				}
			}
		}

		if (NT_ERROR(Status)) {
			break;
		}

		Status = ZwAllocateVirtualMemory(ProcessHandle, reinterpret_cast<void**>(&ParameterAddressBuffer), 0, &ParameterSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (NT_ERROR(Status)) {
			break;
		}

		Status = ZwWriteVirtualMemory(ProcessHandle, ParameterAddressBuffer, &Parameter, sizeof(MappingParameter), &ReturnSize);
		if (NT_ERROR(Status)) {
			break;
		}

		Status = ZwAllocateVirtualMemory(ProcessHandle, reinterpret_cast<void**>(&fBuffer), 0, &fSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (NT_ERROR(Status)) {
			break;
		}

		Status = ZwWriteVirtualMemory(ProcessHandle, fBuffer, f, fSize, &ReturnSize);
		if (NT_ERROR(Status)) {
			break;
		}

		break;
	}

	if (NT_ERROR(Status)) {

		if (fBuffer) {
			ZwFreeVirtualMemory(ProcessHandle, reinterpret_cast<void**>(&fBuffer), &fSize, MEM_DECOMMIT);
		}

		if (ParameterAddressBuffer) {
			ZwFreeVirtualMemory(ProcessHandle, reinterpret_cast<void**>(&ParameterAddressBuffer), &ParameterSize, MEM_DECOMMIT);
		}

		if (ModuleAddress) {
			ZwFreeVirtualMemory(ProcessHandle, reinterpret_cast<void**>(&ModuleAddress), &ModuleSize, MEM_DECOMMIT);
		}

		return false;
	}

	*call_f = reinterpret_cast<unsigned __int64>(fBuffer);

	*ParameterAddress = reinterpret_cast<unsigned __int64>(ParameterAddressBuffer);

	return true;
}