#include <stdint.h>

// 自定义的DOS头结构
typedef struct _MY_IMAGE_DOS_HEADER {
    uint16_t e_magic;    // Magic number
    uint16_t e_cblp;     // Bytes on last page of file
    uint16_t e_cp;       // Pages in file
    uint16_t e_crlc;     // Relocations
    uint16_t e_cparhdr;  // Size of header in paragraphs
    uint16_t e_minalloc; // Minimum extra paragraphs needed
    uint16_t e_maxalloc; // Maximum extra paragraphs needed
    uint16_t e_ss;       // Initial (relative) SS value
    uint16_t e_sp;       // Initial SP value
    uint16_t e_csum;     // Checksum
    uint16_t e_ip;       // Initial IP value
    uint16_t e_cs;       // Initial (relative) CS value
    uint16_t e_lfarlc;   // File address of relocation table
    uint16_t e_ovno;     // Overlay number
    uint16_t e_res[4];   // Reserved words
    uint16_t e_oemid;    // OEM identifier (for e_oeminfo)
    uint16_t e_oeminfo;  // OEM information; e_oemid specific
    uint16_t e_res2[10]; // Reserved words
    int32_t  e_lfanew;   // File address of new exe header
} MY_IMAGE_DOS_HEADER;

// 自定义的PE文件头结构 (标准COFF头)
typedef struct _MY_IMAGE_FILE_HEADER {
    uint16_t Machine;              // 机器类型
    uint16_t NumberOfSections;      // 节的数量
    uint32_t TimeDateStamp;         // 文件创建时间戳
    uint32_t PointerToSymbolTable;  // 符号表指针 (COFF符号表的文件偏移)
    uint32_t NumberOfSymbols;       // 符号的数量
    uint16_t SizeOfOptionalHeader;  // 可选头大小
    uint16_t Characteristics;       // 文件特征
} MY_IMAGE_FILE_HEADER;

// 自定义的32位PE可选头结构
typedef struct _MY_IMAGE_OPTIONAL_HEADER32 {
    uint16_t Magic;                  // 魔数，0x10B表示32位
    uint8_t  MajorLinkerVersion;      // 链接器主版本号
    uint8_t  MinorLinkerVersion;      // 链接器次版本号
    uint32_t SizeOfCode;              // 代码段的总大小
    uint32_t SizeOfInitializedData;   // 已初始化数据段的大小
    uint32_t SizeOfUninitializedData; // 未初始化数据段的大小
    uint32_t AddressOfEntryPoint;     // 入口点RVA
    uint32_t BaseOfCode;              // 代码段的起始RVA
    uint32_t BaseOfData;              // 数据段的起始RVA
    uint32_t ImageBase;               // 镜像的首地址（32位）
    uint32_t SectionAlignment;        // 节对齐
    uint32_t FileAlignment;           // 文件对齐
    uint16_t MajorOperatingSystemVersion; // 操作系统主版本号
    uint16_t MinorOperatingSystemVersion; // 操作系统次版本号
    uint16_t MajorImageVersion;       // 镜像主版本号
    uint16_t MinorImageVersion;       // 镜像次版本号
    uint16_t MajorSubsystemVersion;   // 子系统主版本号
    uint16_t MinorSubsystemVersion;   // 子系统次版本号
    uint32_t Win32VersionValue;       // 保留，必须为0
    uint32_t SizeOfImage;             // 镜像大小（字节）
    uint32_t SizeOfHeaders;           // 所有头的大小
    uint32_t CheckSum;                // 校验和
    uint16_t Subsystem;               // 子系统类型
    uint16_t DllCharacteristics;      // DLL特征
    uint32_t SizeOfStackReserve;      // 保留栈的大小
    uint32_t SizeOfStackCommit;       // 提交栈的大小
    uint32_t SizeOfHeapReserve;       // 保留堆的大小
    uint32_t SizeOfHeapCommit;        // 提交堆的大小
    uint32_t LoaderFlags;             // 加载标志
    uint32_t NumberOfRvaAndSizes;     // 数据目录项数
    struct {
        uint32_t VirtualAddress;      // 数据目录项RVA
        uint32_t Size;                // 数据目录项大小
    } DataDirectory[16];              // 数据目录数组 (16项)
} MY_IMAGE_OPTIONAL_HEADER32;

// 自定义的64位PE可选头结构
typedef struct _MY_IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;                  // 魔数，0x20B表示64位
    uint8_t  MajorLinkerVersion;      // 链接器主版本号
    uint8_t  MinorLinkerVersion;      // 链接器次版本号
    uint32_t SizeOfCode;              // 代码段的总大小
    uint32_t SizeOfInitializedData;   // 已初始化数据段的大小
    uint32_t SizeOfUninitializedData; // 未初始化数据段的大小
    uint32_t AddressOfEntryPoint;     // 入口点RVA
    uint32_t BaseOfCode;              // 代码段的起始RVA
    uint64_t ImageBase;               // 镜像的首地址（64位）
    uint32_t SectionAlignment;        // 节对齐
    uint32_t FileAlignment;           // 文件对齐
    uint16_t MajorOperatingSystemVersion; // 操作系统主版本号
    uint16_t MinorOperatingSystemVersion; // 操作系统次版本号
    uint16_t MajorImageVersion;       // 镜像主版本号
    uint16_t MinorImageVersion;       // 镜像次版本号
    uint16_t MajorSubsystemVersion;   // 子系统主版本号
    uint16_t MinorSubsystemVersion;   // 子系统次版本号
    uint32_t Win32VersionValue;       // 保留，必须为0
    uint32_t SizeOfImage;             // 镜像大小（字节）
    uint32_t SizeOfHeaders;           // 所有头的大小
    uint32_t CheckSum;                // 校验和
    uint16_t Subsystem;               // 子系统类型
    uint16_t DllCharacteristics;      // DLL特征
    uint64_t SizeOfStackReserve;      // 保留栈的大小
    uint64_t SizeOfStackCommit;       // 提交栈的大小
    uint64_t SizeOfHeapReserve;       // 保留堆的大小
    uint64_t SizeOfHeapCommit;        // 提交堆的大小
    uint32_t LoaderFlags;             // 加载标志
    uint32_t NumberOfRvaAndSizes;     // 数据目录项数
    struct {
        uint32_t VirtualAddress;      // 数据目录项RVA
        uint32_t Size;                // 数据目录项大小
    } DataDirectory[16];              // 数据目录数组 (16项)
} MY_IMAGE_OPTIONAL_HEADER64;

// 自定义的节表结构
typedef struct _MY_IMAGE_SECTION_HEADER {
    uint8_t  Name[8];             // 节名称
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;       // 节的RVA
    uint32_t SizeOfRawData;        // 节的大小（文件中）
    uint32_t PointerToRawData;     // 节的文件偏移
    uint32_t PointerToRelocations; // 重定位信息的文件偏移
    uint32_t PointerToLinenumbers; // 行号信息的文件偏移
    uint16_t NumberOfRelocations;  // 重定位信息数量
    uint16_t NumberOfLinenumbers;  // 行号信息数量
    uint32_t Characteristics;      // 节特征
} MY_IMAGE_SECTION_HEADER;

// 自定义的PE头结构体，用于32位PE文件
typedef struct _MY_IMAGE_NT_HEADERS32 {
    uint32_t Signature;                // PE签名，通常为 "PE\0\0" (0x00004550)
    MY_IMAGE_FILE_HEADER FileHeader;   // 标准COFF头
    MY_IMAGE_OPTIONAL_HEADER32 OptionalHeader; // 可选头（32位版本）
} MY_IMAGE_NT_HEADERS32;

// 自定义的PE头结构体，用于64位PE文件
typedef struct _MY_IMAGE_NT_HEADERS64 {
    uint32_t Signature;                // PE签名，通常为 "PE\0\0" (0x00004550)
    MY_IMAGE_FILE_HEADER FileHeader;   // 标准COFF头
    MY_IMAGE_OPTIONAL_HEADER64 OptionalHeader; // 可选头（64位版本）
} MY_IMAGE_NT_HEADERS64;


