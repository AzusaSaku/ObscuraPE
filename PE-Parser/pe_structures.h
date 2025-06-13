#pragma once
#ifndef PE_STRUCTURES_H
#define PE_STRUCTURES_H

#include <algorithm>
#include <cstdint>
#include <vector>
#include <string>

// PE文件常量定义
#define IMAGE_DOS_SIGNATURE                 0x5A4D      // "MZ"
#define IMAGE_NT_SIGNATURE                  0x00004550  // "PE\0\0"
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC       0x10B
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC       0x20B
#define IMAGE_SUBSYSTEM_WINDOWS_GUI         2
#define IMAGE_SUBSYSTEM_WINDOWS_CUI         3
#define IMAGE_DIRECTORY_ENTRY_EXPORT        0
#define IMAGE_DIRECTORY_ENTRY_IMPORT        1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE      2
#define IMAGE_DIRECTORY_ENTRY_BASERELOC     5
#define IMAGE_DIRECTORY_ENTRY_TLS           9
#define IMAGE_SIZEOF_SHORT_NAME             8

// 节区标志
#define IMAGE_SCN_CNT_CODE                  0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA      0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA    0x00000080
#define IMAGE_SCN_MEM_EXECUTE               0x20000000
#define IMAGE_SCN_MEM_READ                  0x40000000
#define IMAGE_SCN_MEM_WRITE                 0x80000000

// DOS头结构
#pragma pack(push, 1)
struct IMAGE_DOS_HEADER {
    uint16_t e_magic;        // "MZ" 签名
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;       // NT头偏移
};
#pragma pack(pop)

// 文件头结构
struct IMAGE_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

// 数据目录结构
struct IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
};

// 32位可选头
struct IMAGE_OPTIONAL_HEADER32 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
};

// 64位可选头
struct IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
};

// NT头结构
struct IMAGE_NT_HEADERS32 {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

struct IMAGE_NT_HEADERS64 {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

// 节区头结构
struct IMAGE_SECTION_HEADER {
    char Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

// 导入描述符
struct IMAGE_IMPORT_DESCRIPTOR {
    union {
        uint32_t Characteristics;
        uint32_t OriginalFirstThunk;  // RVA to IMAGE_THUNK_DATA
    };
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;                   // RVA to DLL name
    uint32_t FirstThunk;             // RVA to IMAGE_THUNK_DATA
};

// 32位Thunk数据
struct IMAGE_THUNK_DATA32 {
    union {
        uint32_t ForwarderString;
        uint32_t Function;
        uint32_t Ordinal;
        uint32_t AddressOfData;      // RVA to IMAGE_IMPORT_BY_NAME
    } u1;
};

// 64位Thunk数据
struct IMAGE_THUNK_DATA64 {
    union {
        uint64_t ForwarderString;
        uint64_t Function;
        uint64_t Ordinal;
        uint64_t AddressOfData;      // RVA to IMAGE_IMPORT_BY_NAME
    } u1;
};

// 导入函数名称
struct IMAGE_IMPORT_BY_NAME {
    uint16_t Hint;
    char Name[1];  // 可变长度
};

// 导出目录
struct IMAGE_EXPORT_DIRECTORY {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;               // RVA to DLL name
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;     // RVA to function RVA array
    uint32_t AddressOfNames;         // RVA to name pointer array
    uint32_t AddressOfNameOrdinals;  // RVA to ordinal array
};

// 基址重定位块
struct IMAGE_BASE_RELOCATION {
    uint32_t VirtualAddress;
    uint32_t SizeOfBlock;
    // WORD TypeOffset[1];  // 可变长度数组
};

// TLS目录（32位）
struct IMAGE_TLS_DIRECTORY32 {
    uint32_t StartAddressOfRawData;
    uint32_t EndAddressOfRawData;
    uint32_t AddressOfIndex;
    uint32_t AddressOfCallBacks;
    uint32_t SizeOfZeroFill;
    uint32_t Characteristics;
};

// TLS目录（64位）
struct IMAGE_TLS_DIRECTORY64 {
    uint64_t StartAddressOfRawData;
    uint64_t EndAddressOfRawData;
    uint64_t AddressOfIndex;
    uint64_t AddressOfCallBacks;
    uint32_t SizeOfZeroFill;
    uint32_t Characteristics;
};

// 资源目录
struct IMAGE_RESOURCE_DIRECTORY {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint16_t NumberOfNamedEntries;
    uint16_t NumberOfIdEntries;
    // IMAGE_RESOURCE_DIRECTORY_ENTRY Entries[];
};

// 资源目录项
struct IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union {
        struct {
            uint32_t NameOffset:31;
            uint32_t NameIsString:1;
        };
        uint32_t Name;
        uint16_t Id;
    };
    union {
        uint32_t OffsetToData;
        struct {
            uint32_t OffsetToDirectory:31;
            uint32_t DataIsDirectory:1;
        };
    };
};

// 资源数据项
struct IMAGE_RESOURCE_DATA_ENTRY {
    uint32_t OffsetToData;
    uint32_t Size;
    uint32_t CodePage;
    uint32_t Reserved;
};

// PE类型枚举
enum class PE_TYPE {
    PE32,
    PE64,
    UNKNOWN
};

// 机器类型枚举
enum MACHINE_TYPE : uint16_t {
    IMAGE_FILE_MACHINE_UNKNOWN   = 0x0,
    IMAGE_FILE_MACHINE_AMD64     = 0x8664,  // x64
    IMAGE_FILE_MACHINE_I386      = 0x14c,   // x86
    IMAGE_FILE_MACHINE_ARM64     = 0xAA64,  // ARM64
    IMAGE_FILE_MACHINE_ARM       = 0x1C0,   // ARM
};

// 辅助函数
namespace PEUtils {
    // 检查PE是否有效
    inline bool IsValidPE(const IMAGE_DOS_HEADER* dosHeader) {
        return dosHeader->e_magic == IMAGE_DOS_SIGNATURE;
    }

    // 判断PE类型 (32/64位)
    inline PE_TYPE GetPEType(const IMAGE_NT_HEADERS32* ntHeaders) {
        if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            return PE_TYPE::PE32;
        if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            return PE_TYPE::PE64;
        return PE_TYPE::UNKNOWN;
    }

    // 节区名称转换为字符串
    inline std::string SectionNameToString(const char name[IMAGE_SIZEOF_SHORT_NAME]) {
        const char* end = std::find(name, name + IMAGE_SIZEOF_SHORT_NAME, '\0');
        const auto len = static_cast<size_t>(end - name);
        return {name, len};
    }

    // 检查节区是否可执行
    inline bool IsSectionExecutable(const IMAGE_SECTION_HEADER& section) {
        return (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    }
}

// RVA转文件偏移计算器
class RVAToOffsetConverter {
public:
    explicit RVAToOffsetConverter(const std::vector<IMAGE_SECTION_HEADER>& sections)
        : sections_(sections) {}

    [[nodiscard]] uint32_t Convert(uint32_t rva) const {
        for (const auto& section : sections_) {
            uint32_t virtualAddr = section.VirtualAddress;
            uint32_t virtualSize = section.Misc.VirtualSize;
            uint32_t rawDataPtr = section.PointerToRawData;

            if (rva >= virtualAddr && rva < virtualAddr + virtualSize) {
                return rawDataPtr + (rva - virtualAddr);
            }
        }
        return 0; // 无效RVA
    }

private:
    const std::vector<IMAGE_SECTION_HEADER>& sections_;
};

#endif //PE_STRUCTURES_H
