#include <stdio.h>//包含了用于标准输入输出操作的函数。printf()（输出） 和 scanf()（输入），用于打印输出和接受用户输入。fopen()、fread()、fseek()、fclose() 属于 stdio.h 头文件。
#include <stdlib.h> //strtoul()。这是一个用于将字符串转换为无符号长整数的函数，定义在 <stdlib.h> 头文件中。
#include <stdint.h>//头文件定义了固定大小的整数类型。如 uint32_t 和 uint64_t，这些类型保证了跨平台的可移植性，因为它们的大小在所有平台上都一致。
#include "mypestruct.h"  //导入自定义PE文件数据结构头文件

// 解析功能函数声明
void parsePE(const char* filePath, uint32_t Y); //提前告知编译器函数的存在，使编译器在编译 main 函数时知道 parsePE 函数的存在以及它的参数类型和返回值。

// main函数调用PE解析函数
int main(int argc, char* argv[]) {
    if (argc != 3) {   
        printf("使用方法：%s <PE文件路径> <RVA值>\n", argv[0]);   //例子：pe.exe targe.exe 0x4404 ；使用pe.exe工具检测targe.exe文件中RVA偏移处在哪个节？并计算出文件中的偏移RAW？
        return 1;
    }

    // 解析用户输入的RVA值
    uint32_t Y = (uint32_t)strtoul(argv[2], NULL, 16);  // 将用户输入的16进制字符串转为uint32_t
    parsePE(argv[1], Y);

    return 0;
}

// 定义解析函数功能
void parsePE(const char* filePath, uint32_t Y) {
    FILE* file = fopen(filePath, "rb");
    if (!file) {
        printf("无法打开文件：%s\n", filePath);
        return;
    }

    // 读取DOS头
    MY_IMAGE_DOS_HEADER dosHeader;
    fread(&dosHeader, sizeof(MY_IMAGE_DOS_HEADER), 1, file);

    // 检查DOS中的魔数
    if (dosHeader.e_magic != 0x5A4D) { // "MZ"
        printf("不是有效的PE文件\n");
        fclose(file);
        return;
    }

    // 定位到PE头
    fseek(file, dosHeader.e_lfanew, SEEK_SET);

    // 读取PE头签名
    uint32_t peSignature;
    fread(&peSignature, sizeof(uint32_t), 1, file);

    // 检查PE头的签名
    if (peSignature != 0x00004550) { // "PE\0\0"
        printf("无效的PE签名\n");
        fclose(file);
        return;
    }

    // 读取文件头
    MY_IMAGE_FILE_HEADER fileHeader;
    fread(&fileHeader, sizeof(MY_IMAGE_FILE_HEADER), 1, file);

    // 判断是32位还是64位PE文件
    uint16_t magic;
    // 定位到可选头
    fseek(file, dosHeader.e_lfanew + sizeof(uint32_t) + sizeof(MY_IMAGE_FILE_HEADER), SEEK_SET);
    fread(&magic, sizeof(uint16_t), 1, file);

    if (magic == 0x10B) {
        // 32位PE文件
        printf("解析32位PE文件...\n");
        MY_IMAGE_NT_HEADERS32 ntHeaders32;
        fseek(file, dosHeader.e_lfanew, SEEK_SET);
        fread(&ntHeaders32, sizeof(MY_IMAGE_NT_HEADERS32), 1, file);

        // 输出32位PE头信息
        printf("入口点地址(偏移量)：0x%X\n", ntHeaders32.OptionalHeader.AddressOfEntryPoint);
        printf("映像基地址：0x%X\n", ntHeaders32.OptionalHeader.ImageBase);
        printf("节的数量：%d\n", ntHeaders32.FileHeader.NumberOfSections);

        // 解析节表并判断RVA
        fseek(file, dosHeader.e_lfanew + sizeof(MY_IMAGE_NT_HEADERS32), SEEK_SET);
        MY_IMAGE_SECTION_HEADER sectionHeader;

        for (int i = 0; i < ntHeaders32.FileHeader.NumberOfSections; i++) {
            fread(&sectionHeader, sizeof(MY_IMAGE_SECTION_HEADER), 1, file);

            uint32_t virtualAddressStart = sectionHeader.VirtualAddress;
            uint32_t virtualAddressEnd = virtualAddressStart + sectionHeader.Misc.VirtualSize;

            uint32_t rawOffsetStart = sectionHeader.PointerToRawData;
            uint32_t rawOffsetEnd = rawOffsetStart + sectionHeader.SizeOfRawData;

            if (virtualAddressStart <= Y && Y < virtualAddressEnd) {
                printf("  RVA=0x%X 在第 %d 节\n", Y, i + 1);
                printf("  内存起始位置（VirtualAddress）：0x%X\n", sectionHeader.VirtualAddress);
                printf("  文件中起始位置（PointerToRawData）：0x%X\n", sectionHeader.PointerToRawData);
                printf("节 %d 名称：%.8s\n", i + 1, sectionHeader.Name);
                printf("  内存偏移范围：0x%X - 0x%X\n", virtualAddressStart, virtualAddressEnd);
                printf("  文件偏移范围：0x%X - 0x%X\n", rawOffsetStart, rawOffsetEnd);
                printf("  RAW=0x%X\n", Y - sectionHeader.VirtualAddress + sectionHeader.PointerToRawData);
                break; // 找到目标节后退出循环
            }
        }
    }
    else if (magic == 0x20B) {
        // 64位PE文件
        printf("解析64位PE文件...\n");
        MY_IMAGE_NT_HEADERS64 ntHeaders64;
        fseek(file, dosHeader.e_lfanew, SEEK_SET);
        fread(&ntHeaders64, sizeof(MY_IMAGE_NT_HEADERS64), 1, file);

        // 输出64位PE头信息
        printf("入口点地址（偏移量）：0x%X\n", ntHeaders64.OptionalHeader.AddressOfEntryPoint);
        printf("映像基地址：0x%llX\n", ntHeaders64.OptionalHeader.ImageBase);
        printf("节的数量：%d\n", ntHeaders64.FileHeader.NumberOfSections);

        // 解析节表并判断RVA
        fseek(file, dosHeader.e_lfanew + sizeof(MY_IMAGE_NT_HEADERS64), SEEK_SET);
        MY_IMAGE_SECTION_HEADER sectionHeader;

        for (int i = 0; i < ntHeaders64.FileHeader.NumberOfSections; i++) {
            fread(&sectionHeader, sizeof(MY_IMAGE_SECTION_HEADER), 1, file);

            uint32_t virtualAddressStart = sectionHeader.VirtualAddress;
            uint32_t virtualAddressEnd = virtualAddressStart + sectionHeader.Misc.VirtualSize;

            uint32_t rawOffsetStart = sectionHeader.PointerToRawData;
            uint32_t rawOffsetEnd = rawOffsetStart + sectionHeader.SizeOfRawData;

            if (virtualAddressStart <= Y && Y < virtualAddressEnd) {
                printf("  RVA=0x%X 在第 %d 节\n", Y, i + 1);
                printf("  内存起始位置（VirtualAddress）：0x%X\n", sectionHeader.VirtualAddress);
                printf("  文件中起始位置（PointerToRawData）：0x%X\n", sectionHeader.PointerToRawData);
                printf("节 %d 名称：%.8s\n", i + 1, sectionHeader.Name);
                printf("  内存偏移范围：0x%X - 0x%X\n", virtualAddressStart, virtualAddressEnd);
                printf("  文件偏移范围：0x%X - 0x%X\n", rawOffsetStart, rawOffsetEnd);
                printf("  RAW=0x%X\n", Y - sectionHeader.VirtualAddress + sectionHeader.PointerToRawData);
                break; // 找到目标节后退出循环
            }
        }
    }
    else {
        printf("未知的PE文件类型，Magic值：0x%X\n", magic);
    }

    fclose(file);
}
