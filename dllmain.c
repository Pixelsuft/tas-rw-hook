#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <Windows.h>
#define ISNULL(ptr) ((ptr) == NULL)
#define HEAP_ARGS HEAP_GENERATE_EXCEPTIONS
#ifdef _DEBUG
#define ENABLE_CONSOLE 1
#else
#define ENABLE_CONSOLE 0
#endif
#define USE_WIDE_CHAR 0
#define CASE_SENS 0

typedef struct {
    char orig_bytes[6];
    char patch[6];
    void* orig_addr;
    void* hook_addr;
} RW_BaseHook;

typedef struct {
#if USE_WIDE_CHAR
    wchar_t fp_buf[MAX_PATH];
#else
    char fp_buf[MAX_PATH];
#endif
    void* ptr;
    char* buf;
    size_t size;
    size_t pos;
} RW_File;

typedef struct {
    RW_File* files[1024];
    RW_BaseHook messageboxa_hook;
    RW_BaseHook createfile_hook;
    RW_BaseHook closehandle_hook;
    RW_BaseHook readfile_hook;
    RW_BaseHook writefile_hook;
    RW_BaseHook setfilepointer_hook;
    HANDLE phandle;
    HANDLE heap;
    HMODULE user32;
    HMODULE kernel32;
    HMODULE hmod;
    size_t files_array_size;
} RW_App;

RW_App* rwh;

void hook_func(RW_BaseHook* bh, void* orig_addr, void* hook_addr) {
    size_t bytes_read;
    bh->orig_addr = orig_addr;
    bh->hook_addr = hook_addr;
    ReadProcessMemory(rwh->phandle, orig_addr, bh->orig_bytes, 6, &bytes_read);
    memset(bh->patch, 0, sizeof(bh->patch));
    memcpy_s(bh->patch, 1, "\x68", 1);
    memcpy_s(bh->patch + 1, 4, &hook_addr, 4);
    memcpy_s(bh->patch + 5, 1, "\xC3", 1);
}

void hook_enable(RW_BaseHook* bh) {
    size_t bytes_written;
    WriteProcessMemory(rwh->phandle, (LPVOID)bh->orig_addr, bh->patch, sizeof(bh->patch), &bytes_written);
}

void hook_disable(RW_BaseHook* bh) {
    size_t bytes_written;
    WriteProcessMemory(rwh->phandle, (LPVOID)bh->orig_addr, bh->orig_bytes, sizeof(bh->orig_bytes), &bytes_written);
}

int __stdcall MessageBoxA_hook(HWND hwnd, LPCSTR text, LPCSTR cap, UINT type) {
    printf("MessageBoxA %s: %s\n", cap, text);
    return IDYES;
}

BOOL __stdcall CloseHandle_hook(HANDLE obj) {
    if (ISNULL(obj))
        return FALSE;
    bool found = false;
    for (size_t i = 0; i < rwh->files_array_size; i++) {
        if (rwh->files[i] == obj) {
            found = true;
            // rwh->files[i] = NULL;
            break;
        }
    }
    if (!found) {
        hook_disable(&rwh->closehandle_hook);
        BOOL res = CloseHandle(obj);
        hook_enable(&rwh->closehandle_hook);
        return res;
    }
    RW_File* file = obj;
    // printf("CloseHandle %p\n", obj);
    // if (!ISNULL(file->buf))
    //     HeapFree(rwh->heap, HEAP_ARGS, file->buf);
    // HeapFree(rwh->heap, HEAP_ARGS, file);
    return TRUE;
}

HANDLE __stdcall CreateFile_hook(
#if USE_WIDE_CHAR
    LPCWSTR _fn,
#else
    LPCSTR _fn,
#endif
    DWORD dw_access, DWORD share_mode, LPSECURITY_ATTRIBUTES sec_attr, DWORD cr_d, DWORD flags, HANDLE template_
) {
    if (ISNULL(_fn))
        return NULL;
#if USE_WIDE_CHAR
    wchar_t fn[MAX_PATH];
    fn[0] = L'\0';
#if CASE_SENS
    wcscpy_s(fn, MAX_PATH, _fn);
#else
    for (size_t i = 0; i < MAX_PATH; i++) {
        fn[i] = towlower(_fn[i]);
        if (_fn[i] == '\0')
            break;
    }
#endif
    wprintf(L"Called opening wide char file: %s\n", fn);
#else
    char fn[MAX_PATH];
    fn[0] = '\0';
#if CASE_SENS
    strcpy_s(fn, MAX_PATH, _fn);
#else
    for (size_t i = 0; i < MAX_PATH; i++) {
        fn[i] = tolower(_fn[i]);
        if (_fn[i] == '\0')
            break;
    }
#endif
#endif
    if ((cr_d < 2) || (cr_d > 3))
        printf("CreateFile %s with cr_d %i\n", fn, (int)cr_d);
    for (size_t i = 0; i < rwh->files_array_size; i++) {
        if (ISNULL(rwh->files[i]))
            continue;
#if USE_WIDE_CHAR
        if (!wcscmp(rwh->files[i]->fp_buf, fn)) {
#else
        if (!strcmp(rwh->files[i]->fp_buf, fn)) {
#endif
            printf("Warning: found the same file %s with cr_d %i !!!!\n", fn, (int)cr_d);
            rwh->files[i]->pos = 0;
            if (cr_d == CREATE_ALWAYS)
                rwh->files[i]->size = 0;
            return rwh->files[i];
        }
    }
    if (cr_d == OPEN_EXISTING) {
#if USE_WIDE_CHAR
        DWORD dw_attrib = GetFileAttributesW(fn);
#else
        DWORD dw_attrib = GetFileAttributesA(fn);
#endif
        if ((dw_attrib == INVALID_FILE_ATTRIBUTES) || (dw_attrib == FILE_ATTRIBUTE_DIRECTORY)) {
            printf("Warn: return NULL\n");
            return INVALID_HANDLE_VALUE;
        }
    }
    RW_File* file = HeapAlloc(rwh->heap, HEAP_ARGS, sizeof(RW_File));
    if (ISNULL(file))
        return NULL;
    for (size_t i = 0; i < rwh->files_array_size; i++) {
        if (ISNULL(rwh->files[i])) {
            rwh->files[i] = file;
            break;
        }
        if (i == rwh->files_array_size - 1) {
            printf("FATAL OUT OF SIZE!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        }
    }
#if USE_WIDE_CHAR
    file->fp_buf[0] = L'\0';
    wcscpy_s(file->fp_buf, MAX_PATH, fn);
#else
    file->fp_buf[0] = '\0';
    strcpy_s(file->fp_buf, MAX_PATH, fn);
#endif
    file->ptr = file;
    file->buf = NULL;
    file->size = 0;
    file->pos = 0;
    if ((dw_access & GENERIC_READ) && (dw_access && GENERIC_WRITE)) {
        // printf("WARNING: opening for both read and write\n");
    }
    if ((dw_access & GENERIC_READ) && (cr_d != CREATE_ALWAYS)) {
        hook_disable(&rwh->createfile_hook);
#if USE_WIDE_CHAR
        HANDLE res = CreateFileW(fn, GENERIC_READ, share_mode, sec_attr, cr_d, flags, template_);
#else
        HANDLE res = CreateFileA(fn, GENERIC_READ, share_mode, sec_attr, cr_d, flags, template_);
#endif
        hook_enable(&rwh->createfile_hook);
        LARGE_INTEGER size_buf;
        if (GetFileSizeEx(res, &size_buf)) {
            file->size = (size_t)size_buf.QuadPart;
            file->buf = HeapAlloc(rwh->heap, HEAP_ARGS, file->size + 1);
            if (ISNULL(file->buf)) {
                printf("Error allocation file buffer\n");
            }
            file->buf[file->size] = '\0';
            DWORD bytes_read;
            if (!ReadFile(res, file->buf, file->size, &bytes_read, NULL)) {
                printf("Failed to read file");
            }
        }
        hook_disable(&rwh->closehandle_hook);
        CloseHandle(res);
        hook_enable(&rwh->closehandle_hook);
    }
    else {
        file->buf = HeapAlloc(rwh->heap, HEAP_ARGS, 1);
    }
    printf("CreateFileA: %s\n", file->fp_buf);
    return file;
}

DWORD __stdcall SetFilePointer_hook(HANDLE _file, LONG to_move, PLONG to_move_high, DWORD move_method) {
    bool found = false;
    for (size_t i = 0; i < rwh->files_array_size; i++) {
        if (rwh->files[i] == _file) {
            found = true;
            break;
        }
    }
    if (!found) {
        hook_disable(&rwh->setfilepointer_hook);
        DWORD res = SetFilePointer(_file, to_move, to_move_high, move_method);
        // DWORD res = 0;
        hook_enable(&rwh->setfilepointer_hook);
        return res;
    }
    RW_File* file = _file;
    if (file->size == 0) {
        file->pos = 0;
        return 0;
    }
    int64_t movement = (int64_t)to_move;
    int64_t cur_pos = (int64_t)file->pos;
    if (move_method == FILE_BEGIN)
        cur_pos = movement;
    else if (move_method == FILE_END) {
        // printf("File end seek warning!!!!!!!!!!!!!!\n");
        cur_pos = (int64_t)file->size + movement;
    }
    else if (move_method == FILE_CURRENT)
        cur_pos += movement;
    /* if (cur_pos < 0)
        cur_pos = 0;
    else if (cur_pos >= (int64_t)file->size)
        cur_pos = (int64_t)file->size - 1; */
    if (cur_pos < 0)
        return ERROR_NEGATIVE_SEEK;
    if (cur_pos >= (int64_t)file->size)
        cur_pos = (int64_t)file->size;
    file->pos = (size_t)cur_pos;
    printf("SeekFilePointer: %s\n", file->fp_buf);
    return (DWORD)file->pos;
}

BOOL __stdcall ReadFile_hook(HANDLE _file, LPVOID buff, DWORD bytes_to_read, LPDWORD bytes_read, LPOVERLAPPED overlapped) {
    if (ISNULL(_file)) {
        return FALSE;
    }
    bool found = false;
    for (size_t i = 0; i < rwh->files_array_size; i++) {
        if (rwh->files[i] == _file) {
            found = true;
            break;
        }
    }
    if (!found) {
        hook_disable(&rwh->readfile_hook);
        BOOL res = ReadFile(_file, buff, bytes_to_read, bytes_read, overlapped);
        hook_enable(&rwh->readfile_hook);
        return res;
    }
    printf("ReadFile %p\n", _file);
    RW_File* file = _file;
    if (file->size == 0) {
        *bytes_read = 0;
        return FALSE;
    }
    size_t to_read = min((size_t)bytes_to_read, file->size - file->pos);
    memcpy(buff, file->buf + file->pos, to_read);
    file->pos += to_read;
    *bytes_read = (DWORD)to_read;
    printf("ReadFile: %s\n", file->fp_buf);
    return TRUE;
}

BOOL __stdcall WriteFile_hook(HANDLE _file, LPCVOID buff, DWORD bytes_to_write, LPDWORD bytes_written, LPOVERLAPPED overlapped) {
    if (ISNULL(_file)) {
        return FALSE;
    }
    bool found = false;
    for (size_t i = 0; i < rwh->files_array_size; i++) {
        if (rwh->files[i] == _file) {
            found = true;
            break;
        }
    }
    if (!found) {
        hook_disable(&rwh->writefile_hook);
        BOOL res = WriteFile(_file, buff, bytes_to_write, bytes_written, overlapped);
        // BOOL res = FALSE;
        hook_enable(&rwh->writefile_hook);
        return res;
    }
    RW_File* file = _file;
    size_t end_pos = (size_t)bytes_to_write + file->pos;
    if (file->size <= end_pos) {
        file->buf = HeapReAlloc(rwh->heap, HEAP_ARGS, file->buf, end_pos + 2);
    }
    file->size = max(file->size, end_pos);
    memcpy(file->buf + file->pos, buff, bytes_to_write);
    *bytes_written = bytes_to_write;
    printf("WriteFile: %s\n", file->fp_buf);
    return TRUE;
}

DWORD WINAPI dll_main_thread(HMODULE hmod) {
    HANDLE _user32, _kernel32;
    _user32 = LoadLibraryExW(L"user32.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    _kernel32 = LoadLibraryExW(L"kernel32.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    // TODO: msvcrt dll 'remove' func
    if (ISNULL(_user32) || ISNULL(_kernel32)) {
        return 1;
    }
    HANDLE _heap = HeapCreate(HEAP_ARGS, 0, 0);
    if (ISNULL(_heap)) {
        return 1;
    }
    rwh = HeapAlloc(_heap, HEAP_ARGS, sizeof(RW_App));
    if (ISNULL(rwh)) {
        HeapDestroy(_heap);
        return 1;
    }
    rwh->hmod = hmod;
    rwh->phandle = GetCurrentProcess();
    rwh->heap = _heap;
    rwh->user32 = _user32;
    rwh->kernel32 = _kernel32;
    rwh->files_array_size = 1024;
    memset(rwh->files, 0, rwh->files_array_size * sizeof(RW_File*));
#if ENABLE_CONSOLE
    AllocConsole();
    freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
    freopen_s((FILE**)stdin, "CONIN$", "r", stdin);
#endif
    hook_func(&rwh->messageboxa_hook, GetProcAddress(rwh->user32, "MessageBoxA"), &MessageBoxA_hook);
    hook_func(&rwh->createfile_hook, GetProcAddress(rwh->kernel32, USE_WIDE_CHAR ? "CreateFileW" : "CreateFileA"), &CreateFile_hook);
    hook_func(&rwh->closehandle_hook, GetProcAddress(rwh->kernel32, "CloseHandle"), &CloseHandle_hook);
    hook_func(&rwh->readfile_hook, GetProcAddress(rwh->kernel32, "ReadFile"), &ReadFile_hook);
    hook_func(&rwh->writefile_hook, GetProcAddress(rwh->kernel32, "WriteFile"), &WriteFile_hook);
    hook_func(&rwh->setfilepointer_hook, GetProcAddress(rwh->kernel32, "SetFilePointer"), &SetFilePointer_hook);
    hook_enable(&rwh->messageboxa_hook);
    hook_enable(&rwh->createfile_hook);
    hook_enable(&rwh->closehandle_hook);
    hook_enable(&rwh->readfile_hook);
    hook_enable(&rwh->writefile_hook);
    hook_enable(&rwh->setfilepointer_hook);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(hModule);
        CreateThread(0, 0, dll_main_thread, hModule, 0, 0);
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

__declspec(dllexport) int test(void) {
    return 0;
}
