#pragma once

#include <Windows.h>
#include <iostream>
#include <string>

constexpr auto STATUS_SUCCESS = 0;

#define STATUS_ACCESS_DENIED             ((NTSTATUS)0xC0000022L)

#define PAGE_SHIFT 12L

#define PAGE_SIZE 0x1000

#define PAGE_ALIGN(Va) ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))

#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define NT_ERROR(Status) ((((ULONG)(Status)) >> 30) == 3)

enum class SYSTEM_INFORMATION_CLASS :unsigned __int32 {

	SystemProcessInformation = 0x5,
	SystemModuleInformation = 0xb,
	SystemPerformanceTraceInformation = 0x1f,
	SystemSupportedProcessArchitectures = 0xb5
};

struct PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	void* PebBaseAddress;
	ULONG_PTR AffinityMask;
	LONG BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
};

enum class ProcessInformationClass :unsigned __int32 {
	ProcessBasicInformation = 0,
};

using fnZwQuerySystemInformation = NTSTATUS(*)(SYSTEM_INFORMATION_CLASS SystemInfoClass, PVOID SystemInfoBuffer, ULONG SystemInfoBufferSize, PULONG BytesReturned);

using fnZwAllocateVirtualMemory = NTSTATUS(*)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

using fnZwFreeVirtualMemory = NTSTATUS(*)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);

using fnZwReadVirtualMemory = NTSTATUS(*)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);

using fnZwWriteVirtualMemory = NTSTATUS(*)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);

using fnZwProtectVirtualMemory = NTSTATUS(*)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);

using fnZwGetNextThread = NTSTATUS(*)(HANDLE ProcessHandle, HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewThreadHandle);

using fnZwQueueApcThreadEx = NTSTATUS(*)(HANDLE ThreadHandle, ULONG Env, void* ApcRoutine, PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);

using fnZwQueryInformationProcess = NTSTATUS(*)(HANDLE ProcessHandle, ProcessInformationClass ProcessInfoClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

inline fnZwQuerySystemInformation ZwQuerySystemInformation;

inline fnZwAllocateVirtualMemory ZwAllocateVirtualMemory;

inline fnZwFreeVirtualMemory ZwFreeVirtualMemory;

inline fnZwReadVirtualMemory ZwReadVirtualMemory;

inline fnZwWriteVirtualMemory ZwWriteVirtualMemory;

inline fnZwProtectVirtualMemory ZwProtectVirtualMemory;

inline fnZwGetNextThread ZwGetNextThread;

inline fnZwQueueApcThreadEx ZwQueueApcThreadEx;

inline fnZwQueryInformationProcess ZwQueryInformationProcess;

typedef void* (*fnLoadLibraryA)(const char* lpLibFileName);
typedef unsigned __int64 (*fnGetProcAddress)(void* hModule, const char* lpProcName);
typedef BOOLEAN(*fnRtlAddFunctionTable)(IMAGE_RUNTIME_FUNCTION_ENTRY* FunctionTable, unsigned __int32 EntryCount, unsigned __int64 BaseAddress);

typedef int (*fnDllMain)(void* hinstDLL, unsigned __int32 fdwReason, void* lpvReserved);

using fnVirtualAlloc = LPVOID(*)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
using fnGetThreadContext = BOOL(*)(HANDLE hThread, LPCONTEXT lpContext);
using fnSetThreadContext = BOOL(*)(HANDLE hThread, CONTEXT* lpContext);
using fnRtlCopyMemory = void(*)(void* Destination, void* Source, unsigned __int64 Length);

using fnMessageBoxA = int (*)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

struct MappingParameter {

	unsigned __int64 ImageBase;

	fnLoadLibraryA fLoadLibraryA;
	fnGetProcAddress fGetProcAddress;
	fnRtlAddFunctionTable fRtlAddFunctionTable;

	fnVirtualAlloc fVirtualAlloc;
	fnRtlCopyMemory fRtlCopyMemory;
	fnGetThreadContext fGetThreadContext;
	fnSetThreadContext fSetThreadContext;

	volatile bool IsExecution;
	volatile bool IsStartDllMain;
};

struct UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWCH   Buffer;
};

struct CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
};

typedef LONG KPRIORITY;

enum KWAIT_REASON {

};

struct SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	KWAIT_REASON WaitReason;
};

struct SYSTEM_PROCESS_INFORMATION {

	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	ULONG BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	ULONG_PTR PeakVirtualSize;
	ULONG_PTR VirtualSize;
	ULONG PageFaultCount;
	ULONG_PTR PeakWorkingSetSize;
	ULONG_PTR WorkingSetSize;
	ULONG_PTR QuotaPeakPagedPoolUsage;
	ULONG_PTR QuotaPagedPoolUsage;
	ULONG_PTR QuotaPeakNonPagedPoolUsage;
	ULONG_PTR QuotaNonPagedPoolUsage;
	ULONG_PTR PagefileUsage;
	ULONG_PTR PeakPagefileUsage;
	ULONG_PTR PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
};

inline auto KiDelayExecutionThread = [](DWORD Second) -> void {

	Sleep(Second * 1000);
};

bool InitSystemRoutineAddress();

bool InitMappingParameter(MappingParameter* Parameter, void* ImageBase);

unsigned __int64 LoadModule(const wchar_t* FileName);

bool MappingModule(HANDLE ProcessHandle, unsigned __int64 ImageBase, void* f, unsigned __int64* call_f, unsigned __int64* ParameterAddress);