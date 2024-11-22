#pragma once

#include <Windows.h>
#include "util.h"

void UserApcRoutine(PVOID* NormalContext, unsigned __int64 fShellcode, unsigned __int64 Parameter);

bool InsertAPC(HANDLE ProcessHandle, unsigned __int64 call_f, unsigned __int64 ParameterAddress);