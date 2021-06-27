#pragma once

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>

#include "ntdef.h"
#include "hook.h"
#include "syscall.h"

#define HOOK(name) {                                                                    \
    PVOID proc = GetProcAddress(ntdll, #name);                                          \
    if (proc) {                                                                         \
        if (TrampolineHook(name##Hook, proc, (PVOID *)&name)) {                         \
            hooks.Src[hooks.Length] = proc;                                             \
            hooks.Original[hooks.Length++] = name;                                      \
        } else {                                                                        \
            MessageBox(0, L"[X] \""L#name##L"\"", L"FAILURE", MB_ICONERROR); \
        }                                                                               \
    } else {                                                                            \
        MessageBox(0, L"[X] \""L#name##L"\"", L"FAILURE", MB_ICONERROR);     \
    }                                                                                   \
}

BOOL SetupSyscalls();
NTSTATUS DoSyscall(SYSCALL syscall, PVOID args);