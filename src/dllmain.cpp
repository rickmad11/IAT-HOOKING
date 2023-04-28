#include "pch.h"

static std::future<int> init_future_obj;

typedef int(__stdcall*OMessageBox)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
OMessageBox originalmessagebox = nullptr;


int __stdcall My_Function(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    MessageBox(0,L"HOOKED",L"HOOKED",0);
    return originalmessagebox(hWnd, lpText, lpCaption, uType);
}

enum class Check_If : uintptr_t
{
    Match = 0,
    No_Match = 1,
    Failed = 0
};

template <typename T>
inline bool operator==(const T value, const Check_If& check) noexcept
{
    return value == static_cast<uintptr_t>(check);
}

PIMAGE_THUNK_DATA GetThunkData(const std::string& Function_To_Replace) {

    uintptr_t Image_Base_Address = reinterpret_cast<uintptr_t>(GetModuleHandleW(NULL));

    if (Image_Base_Address == Check_If::Failed)
    {
        return nullptr;
    }

    PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(Image_Base_Address);
    PIMAGE_NT_HEADERS nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<uintptr_t>(dos_header->e_lfanew) + Image_Base_Address);
    IMAGE_DATA_DIRECTORY data_directory = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR import_descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(static_cast<uintptr_t>(data_directory.VirtualAddress) + Image_Base_Address);
    
    PIMAGE_THUNK_DATA Original_First_Thunk = nullptr, First_Thunk = nullptr;

    while (import_descriptor->Name != NULL)
    {
        //kinda useless at least its not necessary
        HMODULE library = LoadLibraryA(reinterpret_cast<LPCSTR>(import_descriptor->Name)+Image_Base_Address);

        Original_First_Thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(static_cast<uintptr_t>(import_descriptor->OriginalFirstThunk) + Image_Base_Address);
        First_Thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(static_cast<uintptr_t>(import_descriptor->FirstThunk)+Image_Base_Address);

        if (library != NULL) {

            for (; Original_First_Thunk->u1.AddressOfData != NULL; ++First_Thunk, ++Original_First_Thunk)
            {

                const char* Original_Function_Name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(static_cast<uintptr_t>(Original_First_Thunk->u1.AddressOfData) + Image_Base_Address)->Name;

                if (Function_To_Replace.compare(Original_Function_Name) == Check_If::Match)
                {
                    return First_Thunk;
                }

            }
            FreeLibrary(library);
        }
        ++import_descriptor;

    }

    return nullptr;
}

uintptr_t Replace_Original_Function_Hook(uintptr_t* Original_Function_Address) {

    if(Original_Function_Address != NULL){

        originalmessagebox = reinterpret_cast<OMessageBox>(*Original_Function_Address);
        uintptr_t Temp_Saved_Address = *Original_Function_Address;

        DWORD protection;
        VirtualProtect(Original_Function_Address, sizeof(uintptr_t*), PAGE_EXECUTE_READWRITE, &protection);
        *Original_Function_Address = (uintptr_t)My_Function;
        VirtualProtect(Original_Function_Address, sizeof(uintptr_t*), protection, &protection);

        return Temp_Saved_Address;
    }
    else
    {
        return NULL;
    }
}

void Prepare_Detach(uintptr_t* Function) {

    if (Function != nullptr)
    {
        DWORD protection;
        VirtualProtect(Function, sizeof(uintptr_t*), PAGE_EXECUTE_READWRITE, &protection);
        *Function = reinterpret_cast<uintptr_t>(originalmessagebox);
        VirtualProtect(Function, sizeof(uintptr_t*), protection, &protection);
    }
    else
    {
        MessageBox(0, L"Prepare_Detach FAILED", L"FATAL ERROR", MB_ICONWARNING);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        return;
    }

}

int main(LPVOID hModule) {

    PIMAGE_THUNK_DATA Thunk_Data = GetThunkData("MessageBoxA");
    if (Thunk_Data == nullptr)
    {
        MessageBox(0,L"PIMAGE_THUNK_DATA FAILED",L"FATAL ERROR", MB_ICONWARNING);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        return 1;
    }

    uintptr_t Original_Function_Address = Replace_Original_Function_Hook(&Thunk_Data->u1.Function);
    if (Original_Function_Address == NULL)
    {
        MessageBox(0, L"PIMAGE_THUNK_DATA FAILED", L"FATAL ERROR", MB_ICONWARNING);
        Prepare_Detach(&Thunk_Data->u1.Function);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        return 1;
    }

    while (!GetAsyncKeyState(VK_END) & 1)
    {

    }

    Prepare_Detach(&Thunk_Data->u1.Function);
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {

    case DLL_PROCESS_ATTACH: {

        DisableThreadLibraryCalls(hModule);

        //CreateThread is safer here but i wanted to test it that way
        init_future_obj = std::async(std::launch::async, &main, hModule);

        break;
    }

    case DLL_PROCESS_DETACH: {
        break;
    }

    }
    return TRUE;
}

