#include "WuXia.h"

void __WuXia() {

	if (!InitSystemRoutineAddress()) {
		return;
	}

	for (;;) {

		if (!__GetWuXiaProcess()) {
			std::cout << "等待游戏启动" << std::endl;
		}

		KiDelayExecutionThread(10);
	}
}

bool __GetWuXiaProcess() {

	auto ReturnLength = 0ul;
	auto Status = ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, nullptr, 0, &ReturnLength);
	if (Status == STATUS_INFO_LENGTH_MISMATCH) {

		SYSTEM_PROCESS_INFORMATION* ProcessInformation = nullptr;
		auto RegionSize = ReturnLength + 0ull;
		Status = ZwAllocateVirtualMemory(GetCurrentProcess(), reinterpret_cast<void**>(&ProcessInformation), 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
		if (NT_ERROR(Status)) {
			return false;
		}

		Status = ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, ProcessInformation, ReturnLength, &ReturnLength);
		if (NT_ERROR(Status)) {
			ZwFreeVirtualMemory(GetCurrentProcess(), reinterpret_cast<void**>(&ProcessInformation), nullptr, MEM_RELEASE);
			return false;
		}

		for (; ProcessInformation->NextEntryOffset; ProcessInformation = (SYSTEM_PROCESS_INFORMATION*)((unsigned __int64)ProcessInformation + ProcessInformation->NextEntryOffset)) {

			if (!ProcessInformation->ImageName.Length) {
				continue;
			}

			if (!std::wstring(ProcessInformation->ImageName.Buffer).compare(WuXiaName) && WuXiaId.find(ProcessInformation->ProcessId) == WuXiaId.end()) {

				auto ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, false, HandleToULong(ProcessInformation->ProcessId));
				if (!ProcessHandle || ProcessHandle == INVALID_HANDLE_VALUE) {
					continue;
				}

				PROCESS_BASIC_INFORMATION WuXiaBasicInformation = {};
				Status = ZwQueryInformationProcess(ProcessHandle, ProcessInformationClass::ProcessBasicInformation, &WuXiaBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), &ReturnLength);
				if (NT_ERROR(Status)) {
					CloseHandle(ProcessHandle);
					continue;
				}

				auto WuXiaPeb = reinterpret_cast<unsigned __int64>(WuXiaBasicInformation.PebBaseAddress);

				auto PebPadding3 = reinterpret_cast<unsigned __int32*>(WuXiaPeb + 0x010C);

				unsigned __int32 PebPadding3_Data = 0;
				ULONG NumberOfBytesReaded = 0;
				Status = ZwReadVirtualMemory(ProcessHandle, PebPadding3, &PebPadding3_Data, sizeof(unsigned __int32), &NumberOfBytesReaded);
				if (NT_ERROR(Status)) {
					CloseHandle(ProcessHandle);
					continue;
				}

				if (PebPadding3_Data == 0xC128) {
					WuXiaId.insert(ProcessInformation->ProcessId);
					CloseHandle(ProcessHandle);
					continue;
				}

				unsigned __int32 PebPadding3_Flag = 0xC128;
				SIZE_T NumberOfBytesWritten = 0;
				Status = ZwWriteVirtualMemory(ProcessHandle, PebPadding3, &PebPadding3_Flag, sizeof(unsigned __int32), &NumberOfBytesWritten);
				if (NT_ERROR(Status)) {
					CloseHandle(ProcessHandle);
					continue;
				}

				WuXiaId.insert(ProcessInformation->ProcessId);

				auto ImageBase = reinterpret_cast<unsigned __int64>(Bytes);

				unsigned __int64 fShellcodeAddress = 0;

				unsigned __int64 ParameterAddress = 0;

				if (!MappingModule(ProcessHandle, ImageBase, reinterpret_cast<void*>(__call_rip), &fShellcodeAddress, &ParameterAddress)) {
					CloseHandle(ProcessHandle);
					continue;
				}

				if (!InsertAPC(ProcessHandle, fShellcodeAddress, ParameterAddress)) {
					CloseHandle(ProcessHandle);
					continue;
				}

				CloseHandle(ProcessHandle);

				ZwFreeVirtualMemory(GetCurrentProcess(), reinterpret_cast<void**>(&ProcessInformation), nullptr, MEM_RELEASE);

				std::cout << "渲染成功 等待下一次游戏启动" << std::endl;

				std::cout << "Ctrl+Shift+Q 隐藏渲染窗口" << std::endl;

				return true;
			}
		}

		ZwFreeVirtualMemory(GetCurrentProcess(), reinterpret_cast<void**>(&ProcessInformation), nullptr, MEM_RELEASE);

		return false;
	}

	return false;
}

void __call_rip(MappingParameter* Parameter) {

	unsigned __int64 ImageBase = Parameter->ImageBase;

	IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)ImageBase;

	IMAGE_NT_HEADERS* NtHeader = (IMAGE_NT_HEADERS*)(ImageBase + DosHeader->e_lfanew);

	IMAGE_OPTIONAL_HEADER* OptionalHeader = &NtHeader->OptionalHeader;

	unsigned __int64 LocationDelta = ImageBase - OptionalHeader->ImageBase;

	IMAGE_DATA_DIRECTORY RelocationDataDirectory = OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (RelocationDataDirectory.Size > 0) {

		IMAGE_BASE_RELOCATION* RelocationTable = (IMAGE_BASE_RELOCATION*)(ImageBase + RelocationDataDirectory.VirtualAddress);

		for (;;) {

			unsigned __int64 RelocationEntryNumber = (RelocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(short);

			unsigned __int16* RelocationEntry = (unsigned __int16*)(RelocationTable + 1);

			for (int i = 0; i < RelocationEntryNumber; i++, RelocationEntry++) {

				if (*RelocationEntry >> 0x0C == IMAGE_REL_BASED_DIR64) {

					unsigned __int64* address = (unsigned __int64*)(ImageBase + RelocationTable->VirtualAddress + (*RelocationEntry & 0xfff));
					*address += LocationDelta;
				}
			}

			RelocationTable = (IMAGE_BASE_RELOCATION*)((unsigned __int64)RelocationTable + RelocationTable->SizeOfBlock);

			if (RelocationTable->SizeOfBlock == 0) {
				break;
			}
		}
	}

	IMAGE_DATA_DIRECTORY ImportDataDirectory = OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (ImportDataDirectory.Size > 0) {

		IMAGE_IMPORT_DESCRIPTOR* ImportTable = (IMAGE_IMPORT_DESCRIPTOR*)(ImageBase + ImportDataDirectory.VirtualAddress);

		for (;;) {

			if (ImportTable->Name == 0) {
				break;
			}

			void* ModuleHandle = Parameter->fLoadLibraryA((const char*)(ImageBase + ImportTable->Name));

			if (ModuleHandle != NULL) {

				unsigned __int64* ImportNameTable = (unsigned __int64*)(ImageBase + ImportTable->OriginalFirstThunk);
				unsigned __int64* ImportAddressTable = (unsigned __int64*)(ImageBase + ImportTable->FirstThunk);

				for (;;) {

					if (*ImportNameTable == 0 || *ImportAddressTable == 0) {
						break;
					}

					if (IMAGE_SNAP_BY_ORDINAL(*ImportNameTable)) {

						*ImportAddressTable = Parameter->fGetProcAddress(ModuleHandle, (char*)(*ImportNameTable & 0xffff));

					} else {

						IMAGE_IMPORT_BY_NAME* ImportFunctionName = (IMAGE_IMPORT_BY_NAME*)(ImageBase + *ImportNameTable);
						*ImportAddressTable = Parameter->fGetProcAddress(ModuleHandle, ImportFunctionName->Name);
					}

					ImportNameTable++;
					ImportAddressTable++;
				}
			}

			ImportTable++;
		}
	}

	IMAGE_DATA_DIRECTORY TLSDataDirectory = OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

	if (TLSDataDirectory.Size > 0) {

		IMAGE_TLS_DIRECTORY* TLSTable = (IMAGE_TLS_DIRECTORY*)(ImageBase + TLSDataDirectory.VirtualAddress);

		PIMAGE_TLS_CALLBACK* AddressOfCallbacks = (PIMAGE_TLS_CALLBACK*)(TLSTable->AddressOfCallBacks);

		for (;;) {

			if (AddressOfCallbacks == NULL || *AddressOfCallbacks == NULL) {
				break;
			}

			(*AddressOfCallbacks)((void*)ImageBase, 1, NULL);

			AddressOfCallbacks++;
		}
	}

	IMAGE_DATA_DIRECTORY ExceptionDataDirectory = OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

	if (ExceptionDataDirectory.Size > 0) {

		IMAGE_RUNTIME_FUNCTION_ENTRY* ExceptionFunctionTable = (IMAGE_RUNTIME_FUNCTION_ENTRY*)(ImageBase + ExceptionDataDirectory.VirtualAddress);

		if (ExceptionFunctionTable != NULL && ExceptionFunctionTable->BeginAddress != 0) {

			Parameter->fRtlAddFunctionTable(ExceptionFunctionTable, ExceptionDataDirectory.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), ImageBase);
		}
	}

	((fnDllMain)(ImageBase + OptionalHeader->AddressOfEntryPoint))((void*)ImageBase, 1, NULL);
}