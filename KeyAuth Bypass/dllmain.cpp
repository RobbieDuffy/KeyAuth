#include <windows.h>
#include <iostream>
#include "scan.h"
#include "mh.h"

std::string(*encryptorig)(std::string message, std::string enc_key, std::string iv);
std::string encrypt(std::string message, std::string enc_key, std::string iv)
{
    std::cout << "[Encryptor] Encryptor called!" << std::endl;
    return encryptorig(message, enc_key, iv);
}

std::string (*decryptorig)(std::string cipher_text, std::string key, std::string iv);
std::string decrypt(std::string cipher_text, std::string key, std::string iv)
{
    auto ret = decryptorig(cipher_text, key, iv);

    std::cout << "\n\n[Decryptor] Decryptor called!" << std::endl;
    std::cout << "[Decryptor] real returned info  : " << ret << std::endl;
    std::cout << "[Decryptor] key : " << key.c_str() << std::endl;
    std::cout << "[Decryptor] iv : " << iv.c_str() << std::endl;

    {
        std::string pushed = "{\"success\":true,\"message\":\"Logged in!\",\"info\":{\"username\":\"";

        std::string ddd;
        std::cout << "\n\n\n [Decryptor] enter fake key : ";
        std::cin >> ddd;

        pushed = pushed + ddd;
        pushed = pushed + std::string("\",\"subscriptions\":[{\"subscription\":\"default\",\"expiry\":\"7954535040\"}],\"ip\":\"69.69.69.69\"}}");

        std::cout << "\n\n\n";

        std::cout << "[Decryptor] fake info : " << pushed << std::endl;

        return pushed;
    }
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{

    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        MH_Initialize();

        std::cout << "\n\nhomelessm8#1337" << std::endl << std::endl;

        std::cout << "base : 0x" << std::hex << GetModuleHandleA(0) << std::endl << std::endl;

        auto addr = Memory::PatternScan("40 53 56 57 41 56 41 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 49 8B D9");

        std::cout << "exploit address 1 : 0x" << std::hex << addr - (uintptr_t)GetModuleHandleA(0) << std::endl << std::endl;

        MH_CreateHook((LPVOID)addr, (LPVOID)decrypt, (LPVOID*)&decryptorig);
        MH_EnableHook((LPVOID)addr);

        addr = Memory::PatternScan("40 53 56 57 41 54 41 56 41 57 48 81 EC");

        std::cout << "exploit address 2 : 0x" << std::hex << addr - (uintptr_t)GetModuleHandleA(0) << std::endl;

        MH_CreateHook((LPVOID)addr, (LPVOID)encrypt, (LPVOID*)&encryptorig);
        MH_EnableHook((LPVOID)addr);
    }

    return TRUE;
}

