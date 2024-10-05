#include <stdio.h>
#include <stdlib.h>
#include "mypestruct.h" //导入自定义头文件

// 解析功能函数声明
void parsePE(const char* filePath);

// main函数调用PE解析函数
int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("使用方法：%s <PE文件路径>\n", argv[0]);
        return 1;
    }
    parsePE(argv[1]);
    return 0;
}

// 定义解析函数功能
void parsePE(const char* filePath) {
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
    //定位到可选头
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

        // 解析节表
        fseek(file, dosHeader.e_lfanew + sizeof(MY_IMAGE_NT_HEADERS32), SEEK_SET);
        MY_IMAGE_SECTION_HEADER sectionHeader;
        for (int i = 0; i < ntHeaders32.FileHeader.NumberOfSections; i++) {
            fread(&sectionHeader, sizeof(MY_IMAGE_SECTION_HEADER), 1, file);
            printf("节 %d 名称：%.8s\n", i + 1, sectionHeader.Name);
            printf("节 %d 虚拟地址：0x%X\n", i + 1, sectionHeader.VirtualAddress);
            printf("节 %d 大小：0x%X\n", i + 1, sectionHeader.SizeOfRawData);
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

        // 解析节表
        fseek(file, dosHeader.e_lfanew + sizeof(MY_IMAGE_NT_HEADERS64), SEEK_SET);
        MY_IMAGE_SECTION_HEADER sectionHeader;
        for (int i = 0; i < ntHeaders64.FileHeader.NumberOfSections; i++) {
            fread(&sectionHeader, sizeof(MY_IMAGE_SECTION_HEADER), 1, file);
            printf("节 %d 名称：%.8s\n", i + 1, sectionHeader.Name);
            printf("节 %d 虚拟地址：0x%X\n", i + 1, sectionHeader.VirtualAddress);
            printf("节 %d 大小：0x%X\n", i + 1, sectionHeader.SizeOfRawData);
        }
    }
    else {
        printf("未知的PE文件类型，Magic值：0x%X\n", magic);
    }

    fclose(file);
}

