#include "apc.h"

void UserApcRoutine(PVOID* NormalContext, unsigned __int64 fShellcode, unsigned __int64 Parameter) {

	unsigned __int8* Shellcode = reinterpret_cast<unsigned __int8*>(NormalContext);

	auto Mapping = reinterpret_cast<MappingParameter*>(Parameter);

	auto ThreadHandle = reinterpret_cast<HANDLE>(-2);

	CONTEXT ThreadContext;
	ThreadContext.ContextFlags = CONTEXT_ALL;
	if (!Mapping->fGetThreadContext(ThreadHandle, &ThreadContext)) {
		return;
	}

	unsigned __int64 ShellcodeSize = 0x1000;
	unsigned char* ShellcodeAddress = reinterpret_cast<unsigned __int8*>(Mapping->fVirtualAlloc(nullptr, ShellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
	if (!ShellcodeAddress) {
		return;
	}

	Mapping->fRtlCopyMemory(ShellcodeAddress, Shellcode, ShellcodeSize);

	*(unsigned __int64*)&ShellcodeAddress[43] = Parameter;
	*(unsigned __int64*)&ShellcodeAddress[93] = ThreadContext.Rip;
	*(unsigned __int64*)&ShellcodeAddress[101] = fShellcode;

	ThreadContext.Rip = (unsigned __int64)ShellcodeAddress;

	Mapping->fSetThreadContext(ThreadHandle, &ThreadContext);
}

bool InsertAPC(HANDLE ProcessHandle, unsigned __int64 call_f, unsigned __int64 ParameterAddress) {

	NTSTATUS Status = STATUS_SUCCESS;
	HANDLE ThreadHandle = nullptr;

	Status = ZwGetNextThread(ProcessHandle, nullptr, THREAD_ALL_ACCESS, 0, 0, &ThreadHandle);
	if (NT_ERROR(Status)) {
		return false;
	}

	unsigned char* Rip = nullptr;
	unsigned __int64 RipSize = PAGE_SIZE;

	Status = ZwAllocateVirtualMemory(ProcessHandle, reinterpret_cast<void**>(&Rip), 0, &RipSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NT_ERROR(Status)) {
		return false;
	}

	unsigned __int64 ReturnSize = 0;

	Status = ZwWriteVirtualMemory(ProcessHandle, Rip, UserApcRoutine, PAGE_SIZE, &ReturnSize);
	if (NT_ERROR(Status)) {
		return false;
	}

	unsigned char* RipShellcode = nullptr;
	unsigned __int64 RipShellcodeSize = PAGE_SIZE;

	unsigned char Shellcode[] = {

		0x50,										// push rax
		0x51,										// push rcx
		0x52,										// push rdx
		0x53,										// push rbx
		//0x54,										// push rsp
		0x55,										// push rbp
		0x56,										// push rsi
		0x57,										// push rdi 
		0x41, 0x50,									// push r8
		0x41, 0x51,									// push r9
		0x41, 0x52,									// push r10
		0x41, 0x53,									// push r11
		0x41, 0x54,									// push r12
		0x41, 0x55,									// push r13
		0x41, 0x56,									// push r14
		0x41, 0x57,									// push r15

		0x48, 0x89, 0x25, 0x4f, 0x00, 0x00, 0x00,	// mov qword ptr ds:[0x00],rsp
		0x48, 0x83, 0xec, 0x38,						// sub rsp,38
		0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff,	// and rsp, FFFFFFFFFFFFFFF0

		0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// mov rcx,0x00
		0xff, 0x15, 0x2c, 0x00, 0x00, 0x00,			// call 0x00

		0x48, 0x8b, 0x25, 0x2d, 0x00, 0x00, 0x00,	// mov rsp,qword ptr [0x00]

		0x41, 0x5f,									// pop r15
		0x41, 0x5e,									// pop r14
		0x41, 0x5d,									// pop r13
		0x41, 0x5c,									// pop r12
		0x41, 0x5b,									// pop r11
		0x41, 0x5a,									// pop r10
		0x41, 0x59,									// pop r9
		0x41, 0x58,									// pop r8
		0x5f,										// pop rdi
		0x5e,										// pop rsi
		0x5d,										// pop rbp
		//0x5c,										// pop rsp
		0x5b,										// pop rbx
		0x5a,										// pop rdx
		0x59,										// pop rcx
		0x58,										// pop rax

		0xff, 0x25, 0x00, 0x00, 0x00, 0x00,				// jmp 0x00
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// Trap->rip
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// call address
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// save rsp
	};

	Status = ZwAllocateVirtualMemory(ProcessHandle, reinterpret_cast<void**>(&RipShellcode), 0, &RipShellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NT_ERROR(Status)) {
		return false;
	}

	Status = ZwWriteVirtualMemory(ProcessHandle, RipShellcode, Shellcode, sizeof(Shellcode), &ReturnSize);
	if (NT_ERROR(Status)) {
		return false;
	}

	Status = ZwQueueApcThreadEx(ThreadHandle, 1, Rip, reinterpret_cast<void*>(RipShellcode), reinterpret_cast<void*>(call_f), reinterpret_cast<void*>(ParameterAddress));

	CloseHandle(ThreadHandle);

	return NT_SUCCESS(Status);
}