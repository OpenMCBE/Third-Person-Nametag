#ifdef _WIN32
#include <Windows.h>
#include <cstdint>
#include <thread>

static constexpr size_t INSTRUCTION_SIZE = 6;
static uint8_t  g_originalBytes[INSTRUCTION_SIZE] = {};
static void*    g_instructionPointer = nullptr;
static bool     g_patched = false;

constexpr uint8_t THIRD_PERSON_NAMETAG_SIG[] = {
    0x0F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x49, 0x8B, 0x45, 0x00, 0x49, 0x8B, 0xCD, 0x48, 0x8B, 0x80,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x84, 0xC0, 0x0F, 0x85
};

constexpr uint8_t THIRD_PERSON_NAMETAG_MASK[] = {
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
};

static uintptr_t FindPattern(uintptr_t base, size_t size,
                             const uint8_t* pattern, const uint8_t* mask, size_t patternLen) {
    const uint8_t* data = reinterpret_cast<const uint8_t*>(base);
    for (size_t i = 0; i < size - patternLen; ++i) {
        bool found = true;
        for (size_t j = 0; j < patternLen; ++j) {
            if (mask[j] == 0xFF && data[i + j] != pattern[j]) {
                found = false;
                break;
            }
        }
        if (found) return base + i;
    }
    return 0;
}

static void ApplyPatch() {
    if (!g_instructionPointer || g_patched) return;
    DWORD protect;
    VirtualProtect(g_instructionPointer, INSTRUCTION_SIZE, PAGE_EXECUTE_READWRITE, &protect);
    memset(g_instructionPointer, 0x90, INSTRUCTION_SIZE);
    VirtualProtect(g_instructionPointer, INSTRUCTION_SIZE, protect, &protect);
    g_patched = true;
}

static void RemovePatch() {
    if (!g_instructionPointer || !g_patched) return;
    DWORD protect;
    VirtualProtect(g_instructionPointer, INSTRUCTION_SIZE, PAGE_EXECUTE_READWRITE, &protect);
    memcpy(g_instructionPointer, g_originalBytes, INSTRUCTION_SIZE);
    VirtualProtect(g_instructionPointer, INSTRUCTION_SIZE, protect, &protect);
    g_patched = false;
}

static void Initialize() {
    HMODULE base = GetModuleHandleA(nullptr);
    if (!base) return;

    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uintptr_t>(base) + dosHeader->e_lfanew);
    size_t sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;

    uintptr_t targetAddr = FindPattern(
        reinterpret_cast<uintptr_t>(base), sizeOfImage,
        THIRD_PERSON_NAMETAG_SIG, THIRD_PERSON_NAMETAG_MASK,
        sizeof(THIRD_PERSON_NAMETAG_SIG));

    if (targetAddr) {
        g_instructionPointer = reinterpret_cast<void*>(targetAddr);
        memcpy(g_originalBytes, g_instructionPointer, INSTRUCTION_SIZE);
        ApplyPatch();
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID /*reserved*/) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        std::thread(Initialize).detach();
    } else if (reason == DLL_PROCESS_DETACH) {
        RemovePatch();
    }
    return TRUE;
}

#else
#include <cstdint>
#include <cstring>
#include <sys/mman.h>

#include "pl/Gloss.h"
#include "pl/Signature.h"

static const char* NAMETAG_SIGNATURE =
        "? ? 40 F9 "
        "? ? ? EB "
        "? ? ? 54 "
        "? ? 40 F9 "
        "? 81 40 F9 "
        "E0 03 ? AA "
        "00 01 3F D6 "
        "? ? 00 37 "
        "? ? 40 F9 "
        "? ? ? A9 "
        "? ? ? CB "
        "? ? ? D3 "
        "? ? 00 51 "
        "? ? ? 8A";

static constexpr size_t PATCH_OFFSET = 8;

static const uint8_t PATCH_BYTES[4] = { 0x1F, 0x20, 0x03, 0xD5 };
static const size_t  PATCH_SIZE     = sizeof(PATCH_BYTES);

static bool PatchMemory(void* addr, const void* data, size_t size) {
    uintptr_t page_start = (uintptr_t)addr & ~(4095UL);
    size_t    page_size  = ((uintptr_t)addr + size - page_start + 4095) & ~(4095UL);

    if (mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        return false;
    }

    memcpy(addr, data, size);
    __builtin___clear_cache((char*)addr, (char*)addr + size);
    mprotect((void*)page_start, page_size, PROT_READ | PROT_EXEC);

    return true;
}

static bool PatchNametag() {
    uintptr_t addr = pl::signature::pl_resolve_signature(NAMETAG_SIGNATURE, "libminecraftpe.so");
    if (addr == 0) {
        return false;
    }

    void* patch_target = reinterpret_cast<void*>(addr + PATCH_OFFSET);
    return PatchMemory(patch_target, PATCH_BYTES, PATCH_SIZE);
}

__attribute__((constructor))
void ThirdPersonNametag_Init() {
    GlossInit(true);
    PatchNametag();
}

#endif
