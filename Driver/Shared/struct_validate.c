/*
 * struct_validate.c
 *
 * Compile-time validation of IOCTL struct sizes and field offsets.
 * This file is compiled as a standalone usermode check (cl.exe) in CI
 * to catch accidental struct layout changes that would break the
 * kernel <-> usermode ABI.
 *
 * Build: cl.exe /nologo /W4 /WX /c struct_validate.c
 *        (no linking needed — all checks are compile-time)
 */

#define WIN32_LEAN_AND_MEAN
#include "ioctl.h"

#include <stddef.h>  /* offsetof */

/* -----------------------------------------------------------------------
 * Helper: FIELD_OFFSET fallback — use offsetof from <stddef.h>
 * In kernel builds FIELD_OFFSET is provided by ntddk.h, but for
 * usermode validation we just use standard offsetof.
 * ----------------------------------------------------------------------- */
#ifndef FIELD_OFFSET
#define FIELD_OFFSET(type, field) offsetof(type, field)
#endif

/* =======================================================================
 * MEMORY_REQUEST  (4 x ULONG64 = 32 bytes)
 * ======================================================================= */
_Static_assert(sizeof(MEMORY_REQUEST) == 32,
    "MEMORY_REQUEST size must be 32 bytes");
_Static_assert(FIELD_OFFSET(MEMORY_REQUEST, ProcessId) == 0,
    "MEMORY_REQUEST.ProcessId must be at offset 0");
_Static_assert(FIELD_OFFSET(MEMORY_REQUEST, Address) == 8,
    "MEMORY_REQUEST.Address must be at offset 8");
_Static_assert(FIELD_OFFSET(MEMORY_REQUEST, Buffer) == 16,
    "MEMORY_REQUEST.Buffer must be at offset 16");
_Static_assert(FIELD_OFFSET(MEMORY_REQUEST, Size) == 24,
    "MEMORY_REQUEST.Size must be at offset 24");

/* =======================================================================
 * MEMORY_RESPONSE  (ULONG64 + LONG, padded to 16 bytes)
 * ======================================================================= */
_Static_assert(sizeof(MEMORY_RESPONSE) == 16,
    "MEMORY_RESPONSE size must be 16 bytes");
_Static_assert(FIELD_OFFSET(MEMORY_RESPONSE, BytesTransferred) == 0,
    "MEMORY_RESPONSE.BytesTransferred must be at offset 0");
_Static_assert(FIELD_OFFSET(MEMORY_RESPONSE, Status) == 8,
    "MEMORY_RESPONSE.Status must be at offset 8");

/* =======================================================================
 * PROCESS_BASE_REQUEST  (1 x ULONG64 = 8 bytes)
 * ======================================================================= */
_Static_assert(sizeof(PROCESS_BASE_REQUEST) == 8,
    "PROCESS_BASE_REQUEST size must be 8 bytes");
_Static_assert(FIELD_OFFSET(PROCESS_BASE_REQUEST, ProcessId) == 0,
    "PROCESS_BASE_REQUEST.ProcessId must be at offset 0");

/* =======================================================================
 * PROCESS_BASE_RESPONSE  (ULONG64 + LONG, padded to 16 bytes)
 * ======================================================================= */
_Static_assert(sizeof(PROCESS_BASE_RESPONSE) == 16,
    "PROCESS_BASE_RESPONSE size must be 16 bytes");
_Static_assert(FIELD_OFFSET(PROCESS_BASE_RESPONSE, BaseAddress) == 0,
    "PROCESS_BASE_RESPONSE.BaseAddress must be at offset 0");
_Static_assert(FIELD_OFFSET(PROCESS_BASE_RESPONSE, Status) == 8,
    "PROCESS_BASE_RESPONSE.Status must be at offset 8");

/* =======================================================================
 * MODULE_BASE_REQUEST  (ULONG64 + WCHAR[256] = 520 bytes)
 * ======================================================================= */
_Static_assert(sizeof(MODULE_BASE_REQUEST) == 520,
    "MODULE_BASE_REQUEST size must be 520 bytes");
_Static_assert(FIELD_OFFSET(MODULE_BASE_REQUEST, ProcessId) == 0,
    "MODULE_BASE_REQUEST.ProcessId must be at offset 0");
_Static_assert(FIELD_OFFSET(MODULE_BASE_REQUEST, ModuleName) == 8,
    "MODULE_BASE_REQUEST.ModuleName must be at offset 8");

/* =======================================================================
 * MODULE_BASE_RESPONSE  (2 x ULONG64 + LONG, padded to 24 bytes)
 * ======================================================================= */
_Static_assert(sizeof(MODULE_BASE_RESPONSE) == 24,
    "MODULE_BASE_RESPONSE size must be 24 bytes");
_Static_assert(FIELD_OFFSET(MODULE_BASE_RESPONSE, BaseAddress) == 0,
    "MODULE_BASE_RESPONSE.BaseAddress must be at offset 0");
_Static_assert(FIELD_OFFSET(MODULE_BASE_RESPONSE, ModuleSize) == 8,
    "MODULE_BASE_RESPONSE.ModuleSize must be at offset 8");
_Static_assert(FIELD_OFFSET(MODULE_BASE_RESPONSE, Status) == 16,
    "MODULE_BASE_RESPONSE.Status must be at offset 16");

/* =======================================================================
 * HIDE_THREADS_REQUEST  (1 x ULONG64 = 8 bytes)
 * ======================================================================= */
_Static_assert(sizeof(HIDE_THREADS_REQUEST) == 8,
    "HIDE_THREADS_REQUEST size must be 8 bytes");
_Static_assert(FIELD_OFFSET(HIDE_THREADS_REQUEST, ProcessId) == 0,
    "HIDE_THREADS_REQUEST.ProcessId must be at offset 0");

/* =======================================================================
 * HIDE_THREADS_RESPONSE  (LONG + ULONG = 8 bytes)
 * ======================================================================= */
_Static_assert(sizeof(HIDE_THREADS_RESPONSE) == 8,
    "HIDE_THREADS_RESPONSE size must be 8 bytes");
_Static_assert(FIELD_OFFSET(HIDE_THREADS_RESPONSE, Status) == 0,
    "HIDE_THREADS_RESPONSE.Status must be at offset 0");
_Static_assert(FIELD_OFFSET(HIDE_THREADS_RESPONSE, ThreadsHidden) == 4,
    "HIDE_THREADS_RESPONSE.ThreadsHidden must be at offset 4");

/* =======================================================================
 * CALLBACK_ENTRY  (ULONG + padding + ULONG64 = 16 bytes)
 * ======================================================================= */
_Static_assert(sizeof(CALLBACK_ENTRY) == 16,
    "CALLBACK_ENTRY size must be 16 bytes");
_Static_assert(FIELD_OFFSET(CALLBACK_ENTRY, Index) == 0,
    "CALLBACK_ENTRY.Index must be at offset 0");
_Static_assert(FIELD_OFFSET(CALLBACK_ENTRY, Address) == 8,
    "CALLBACK_ENTRY.Address must be at offset 8");

/* =======================================================================
 * ENUM_CALLBACKS_REQUEST  (1 x ULONG = 4 bytes)
 * ======================================================================= */
_Static_assert(sizeof(ENUM_CALLBACKS_REQUEST) == 4,
    "ENUM_CALLBACKS_REQUEST size must be 4 bytes");
_Static_assert(FIELD_OFFSET(ENUM_CALLBACKS_REQUEST, CallbackType) == 0,
    "ENUM_CALLBACKS_REQUEST.CallbackType must be at offset 0");

/* =======================================================================
 * ENUM_CALLBACKS_RESPONSE  (LONG + ULONG + CALLBACK_ENTRY[64] = 1032 bytes)
 * ======================================================================= */
_Static_assert(sizeof(ENUM_CALLBACKS_RESPONSE) == 1032,
    "ENUM_CALLBACKS_RESPONSE size must be 1032 bytes");
_Static_assert(FIELD_OFFSET(ENUM_CALLBACKS_RESPONSE, Status) == 0,
    "ENUM_CALLBACKS_RESPONSE.Status must be at offset 0");
_Static_assert(FIELD_OFFSET(ENUM_CALLBACKS_RESPONSE, Count) == 4,
    "ENUM_CALLBACKS_RESPONSE.Count must be at offset 4");
_Static_assert(FIELD_OFFSET(ENUM_CALLBACKS_RESPONSE, Entries) == 8,
    "ENUM_CALLBACKS_RESPONSE.Entries must be at offset 8");

/* =======================================================================
 * REMOVE_CALLBACK_REQUEST  (2 x ULONG = 8 bytes)
 * ======================================================================= */
_Static_assert(sizeof(REMOVE_CALLBACK_REQUEST) == 8,
    "REMOVE_CALLBACK_REQUEST size must be 8 bytes");
_Static_assert(FIELD_OFFSET(REMOVE_CALLBACK_REQUEST, CallbackType) == 0,
    "REMOVE_CALLBACK_REQUEST.CallbackType must be at offset 0");
_Static_assert(FIELD_OFFSET(REMOVE_CALLBACK_REQUEST, Index) == 4,
    "REMOVE_CALLBACK_REQUEST.Index must be at offset 4");

/* =======================================================================
 * REMOVE_CALLBACK_RESPONSE  (1 x LONG = 4 bytes)
 * ======================================================================= */
_Static_assert(sizeof(REMOVE_CALLBACK_RESPONSE) == 4,
    "REMOVE_CALLBACK_RESPONSE size must be 4 bytes");
_Static_assert(FIELD_OFFSET(REMOVE_CALLBACK_RESPONSE, Status) == 0,
    "REMOVE_CALLBACK_RESPONSE.Status must be at offset 0");

/* =======================================================================
 * STRIP_HANDLES_REQUEST  (1 x ULONG64 = 8 bytes)
 * ======================================================================= */
_Static_assert(sizeof(STRIP_HANDLES_REQUEST) == 8,
    "STRIP_HANDLES_REQUEST size must be 8 bytes");
_Static_assert(FIELD_OFFSET(STRIP_HANDLES_REQUEST, ProcessId) == 0,
    "STRIP_HANDLES_REQUEST.ProcessId must be at offset 0");

/* =======================================================================
 * STRIP_HANDLES_RESPONSE  (LONG + ULONG = 8 bytes)
 * ======================================================================= */
_Static_assert(sizeof(STRIP_HANDLES_RESPONSE) == 8,
    "STRIP_HANDLES_RESPONSE size must be 8 bytes");
_Static_assert(FIELD_OFFSET(STRIP_HANDLES_RESPONSE, Status) == 0,
    "STRIP_HANDLES_RESPONSE.Status must be at offset 0");
_Static_assert(FIELD_OFFSET(STRIP_HANDLES_RESPONSE, HandlesStripped) == 4,
    "STRIP_HANDLES_RESPONSE.HandlesStripped must be at offset 4");

/* =======================================================================
 * ARTIFACT_ENTRY  (ULONG + WCHAR[260] = 524 bytes)
 * ======================================================================= */
_Static_assert(sizeof(ARTIFACT_ENTRY) == 524,
    "ARTIFACT_ENTRY size must be 524 bytes");
_Static_assert(FIELD_OFFSET(ARTIFACT_ENTRY, Type) == 0,
    "ARTIFACT_ENTRY.Type must be at offset 0");
_Static_assert(FIELD_OFFSET(ARTIFACT_ENTRY, Path) == 4,
    "ARTIFACT_ENTRY.Path must be at offset 4");

/* =======================================================================
 * SCAN_ARTIFACTS_REQUEST  (WCHAR[256] + ULONG = 516 bytes)
 * ======================================================================= */
_Static_assert(sizeof(SCAN_ARTIFACTS_REQUEST) == 516,
    "SCAN_ARTIFACTS_REQUEST size must be 516 bytes");
_Static_assert(FIELD_OFFSET(SCAN_ARTIFACTS_REQUEST, ExecutableName) == 0,
    "SCAN_ARTIFACTS_REQUEST.ExecutableName must be at offset 0");
_Static_assert(FIELD_OFFSET(SCAN_ARTIFACTS_REQUEST, ArtifactTypes) == 512,
    "SCAN_ARTIFACTS_REQUEST.ArtifactTypes must be at offset 512");

/* =======================================================================
 * SCAN_ARTIFACTS_RESPONSE  (LONG + ULONG + ARTIFACT_ENTRY[128] = 67080 bytes)
 * ======================================================================= */
_Static_assert(sizeof(SCAN_ARTIFACTS_RESPONSE) == 67080,
    "SCAN_ARTIFACTS_RESPONSE size must be 67080 bytes");
_Static_assert(FIELD_OFFSET(SCAN_ARTIFACTS_RESPONSE, Status) == 0,
    "SCAN_ARTIFACTS_RESPONSE.Status must be at offset 0");
_Static_assert(FIELD_OFFSET(SCAN_ARTIFACTS_RESPONSE, Count) == 4,
    "SCAN_ARTIFACTS_RESPONSE.Count must be at offset 4");
_Static_assert(FIELD_OFFSET(SCAN_ARTIFACTS_RESPONSE, Entries) == 8,
    "SCAN_ARTIFACTS_RESPONSE.Entries must be at offset 8");

/* =======================================================================
 * HIDE_PROCESS_REQUEST  (1 x ULONG64 = 8 bytes)
 * ======================================================================= */
_Static_assert(sizeof(HIDE_PROCESS_REQUEST) == 8,
    "HIDE_PROCESS_REQUEST size must be 8 bytes");
_Static_assert(FIELD_OFFSET(HIDE_PROCESS_REQUEST, ProcessId) == 0,
    "HIDE_PROCESS_REQUEST.ProcessId must be at offset 0");

/* =======================================================================
 * HIDE_PROCESS_RESPONSE  (1 x LONG = 4 bytes)
 * ======================================================================= */
_Static_assert(sizeof(HIDE_PROCESS_RESPONSE) == 4,
    "HIDE_PROCESS_RESPONSE size must be 4 bytes");
_Static_assert(FIELD_OFFSET(HIDE_PROCESS_RESPONSE, Status) == 0,
    "HIDE_PROCESS_RESPONSE.Status must be at offset 0");

/* =======================================================================
 * ELEVATE_TOKEN_REQUEST  (1 x ULONG64 = 8 bytes)
 * ======================================================================= */
_Static_assert(sizeof(ELEVATE_TOKEN_REQUEST) == 8,
    "ELEVATE_TOKEN_REQUEST size must be 8 bytes");
_Static_assert(FIELD_OFFSET(ELEVATE_TOKEN_REQUEST, ProcessId) == 0,
    "ELEVATE_TOKEN_REQUEST.ProcessId must be at offset 0");

/* =======================================================================
 * ELEVATE_TOKEN_RESPONSE  (1 x LONG = 4 bytes)
 * ======================================================================= */
_Static_assert(sizeof(ELEVATE_TOKEN_RESPONSE) == 4,
    "ELEVATE_TOKEN_RESPONSE size must be 4 bytes");
_Static_assert(FIELD_OFFSET(ELEVATE_TOKEN_RESPONSE, Status) == 0,
    "ELEVATE_TOKEN_RESPONSE.Status must be at offset 0");

/* =======================================================================
 * PROCESS_TAMPER_REQUEST  (ULONG + ULONG + ULONG64 + union = 32 bytes)
 * ======================================================================= */
_Static_assert(sizeof(PROCESS_TAMPER_REQUEST) == 32,
    "PROCESS_TAMPER_REQUEST size must be 32 bytes");
_Static_assert(FIELD_OFFSET(PROCESS_TAMPER_REQUEST, SubCommand) == 0,
    "PROCESS_TAMPER_REQUEST.SubCommand must be at offset 0");
_Static_assert(FIELD_OFFSET(PROCESS_TAMPER_REQUEST, ProcessId) == 8,
    "PROCESS_TAMPER_REQUEST.ProcessId must be at offset 8");

/* =======================================================================
 * PROCESS_TAMPER_RESPONSE  (LONG + ULONG + ULONG64 = 16 bytes)
 * ======================================================================= */
_Static_assert(sizeof(PROCESS_TAMPER_RESPONSE) == 16,
    "PROCESS_TAMPER_RESPONSE size must be 16 bytes");
_Static_assert(FIELD_OFFSET(PROCESS_TAMPER_RESPONSE, Status) == 0,
    "PROCESS_TAMPER_RESPONSE.Status must be at offset 0");
_Static_assert(FIELD_OFFSET(PROCESS_TAMPER_RESPONSE, PreviousValue) == 8,
    "PROCESS_TAMPER_RESPONSE.PreviousValue must be at offset 8");

/* =======================================================================
 * INJECT_REQUEST  (ULONG + ULONG + ULONG64 + union)
 * Largest union member: DllInject (WCHAR[256] = 512 bytes)
 * Total: 4 + 4 + 8 + 512 = 528 bytes
 * ======================================================================= */
_Static_assert(sizeof(INJECT_REQUEST) == 528,
    "INJECT_REQUEST size must be 528 bytes");
_Static_assert(FIELD_OFFSET(INJECT_REQUEST, SubCommand) == 0,
    "INJECT_REQUEST.SubCommand must be at offset 0");
_Static_assert(FIELD_OFFSET(INJECT_REQUEST, ProcessId) == 8,
    "INJECT_REQUEST.ProcessId must be at offset 8");

/* =======================================================================
 * INJECT_RESPONSE  (LONG + ULONG + 2 x ULONG64 = 24 bytes)
 * ======================================================================= */
_Static_assert(sizeof(INJECT_RESPONSE) == 24,
    "INJECT_RESPONSE size must be 24 bytes");
_Static_assert(FIELD_OFFSET(INJECT_RESPONSE, Status) == 0,
    "INJECT_RESPONSE.Status must be at offset 0");
_Static_assert(FIELD_OFFSET(INJECT_RESPONSE, AllocatedAddress) == 8,
    "INJECT_RESPONSE.AllocatedAddress must be at offset 8");
_Static_assert(FIELD_OFFSET(INJECT_RESPONSE, PreviousValue) == 16,
    "INJECT_RESPONSE.PreviousValue must be at offset 16");

/* =======================================================================
 * SUPPRESS_TELEMETRY_REQUEST  (ULONG + ULONG + ULONG64 = 16 bytes)
 * ======================================================================= */
_Static_assert(sizeof(SUPPRESS_TELEMETRY_REQUEST) == 16,
    "SUPPRESS_TELEMETRY_REQUEST size must be 16 bytes");
_Static_assert(FIELD_OFFSET(SUPPRESS_TELEMETRY_REQUEST, SubCommand) == 0,
    "SUPPRESS_TELEMETRY_REQUEST.SubCommand must be at offset 0");
_Static_assert(FIELD_OFFSET(SUPPRESS_TELEMETRY_REQUEST, Enable) == 4,
    "SUPPRESS_TELEMETRY_REQUEST.Enable must be at offset 4");
_Static_assert(FIELD_OFFSET(SUPPRESS_TELEMETRY_REQUEST, ProcessId) == 8,
    "SUPPRESS_TELEMETRY_REQUEST.ProcessId must be at offset 8");

/* =======================================================================
 * SUPPRESS_TELEMETRY_RESPONSE  (LONG + ULONG + ULONG64 = 16 bytes)
 * ======================================================================= */
_Static_assert(sizeof(SUPPRESS_TELEMETRY_RESPONSE) == 16,
    "SUPPRESS_TELEMETRY_RESPONSE size must be 16 bytes");
_Static_assert(FIELD_OFFSET(SUPPRESS_TELEMETRY_RESPONSE, Status) == 0,
    "SUPPRESS_TELEMETRY_RESPONSE.Status must be at offset 0");
_Static_assert(FIELD_OFFSET(SUPPRESS_TELEMETRY_RESPONSE, PreviousValue) == 8,
    "SUPPRESS_TELEMETRY_RESPONSE.PreviousValue must be at offset 8");

/* =======================================================================
 * Cross-struct consistency checks
 * ======================================================================= */

/* All pointer-width fields must be ULONG64 (8 bytes) for WoW64 safety */
_Static_assert(sizeof(((MEMORY_REQUEST *)0)->ProcessId) == 8,
    "MEMORY_REQUEST.ProcessId must be 8 bytes (ULONG64)");
_Static_assert(sizeof(((MEMORY_REQUEST *)0)->Address) == 8,
    "MEMORY_REQUEST.Address must be 8 bytes (ULONG64)");
_Static_assert(sizeof(((MEMORY_REQUEST *)0)->Buffer) == 8,
    "MEMORY_REQUEST.Buffer must be 8 bytes (ULONG64)");
_Static_assert(sizeof(((CALLBACK_ENTRY *)0)->Address) == 8,
    "CALLBACK_ENTRY.Address must be 8 bytes (ULONG64)");

/* Array capacity constants match actual array sizes */
_Static_assert(sizeof(((ENUM_CALLBACKS_RESPONSE *)0)->Entries) ==
    MAX_CALLBACK_ENTRIES * sizeof(CALLBACK_ENTRY),
    "ENUM_CALLBACKS_RESPONSE.Entries array size mismatch");
_Static_assert(sizeof(((SCAN_ARTIFACTS_RESPONSE *)0)->Entries) ==
    MAX_ARTIFACT_ENTRIES * sizeof(ARTIFACT_ENTRY),
    "SCAN_ARTIFACTS_RESPONSE.Entries array size mismatch");
_Static_assert(sizeof(((MODULE_BASE_REQUEST *)0)->ModuleName) ==
    MAX_MODULE_NAME_LENGTH * sizeof(WCHAR),
    "MODULE_BASE_REQUEST.ModuleName array size mismatch");
_Static_assert(sizeof(((ARTIFACT_ENTRY *)0)->Path) ==
    MAX_ARTIFACT_PATH * sizeof(WCHAR),
    "ARTIFACT_ENTRY.Path array size mismatch");
