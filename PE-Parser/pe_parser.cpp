#include "pe_parser.h"
#include <iostream>
#include <cstring>
#include <optional>
#include <fstream>

PEParser::PEParser(std::string filepath)
    : filepath_(std::move(filepath)) {}

bool PEParser::LoadFile() {
    std::ifstream file(filepath_, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "Error: Failed to open file: " << filepath_ << "\n";
        return false;
    }

    const auto size = file.tellg();
    if (size <= 0) {
        std::cerr << "Error: File is empty or invalid: " << filepath_ << "\n";
        return false;
    }

    rawData_.resize(static_cast<size_t>(size));
    file.seekg(0);
    file.read(reinterpret_cast<char*>(rawData_.data()), size);
    return file.good();
}

bool PEParser::Parse() {
    if (isParsed_) return true; // 避免重复解析

    if (!LoadFile()) {
        return false;
    }

    // 检查DOS头
    if (!IsWithinBounds<IMAGE_DOS_HEADER>(0)) {
        std::cerr << "Error: File too small to contain DOS header\n";
        return false;
    }

    dosHeader_ = *reinterpret_cast<const IMAGE_DOS_HEADER*>(rawData_.data());
    if (!PEUtils::IsValidPE(&dosHeader_)) {
        std::cerr << "Invalid DOS signature (MZ)\n";
        return false;
    }

    // 检查NT头位置
    const size_t ntHeaderOffset = dosHeader_.e_lfanew;
    if (!IsWithinBounds<uint32_t>(ntHeaderOffset)) {
        std::cerr << "Error: NT header offset out of bounds\n";
        return false;
    }

    // 验证PE签名
    const auto signature = *reinterpret_cast<const uint32_t*>(&rawData_[ntHeaderOffset]);
    if (signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "Invalid PE signature (PE\\0\\0)\n";
        return false;
    }

    // 解析NT头
    const size_t optionalHeaderOffset = ntHeaderOffset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER);
    if (!IsWithinBounds<uint16_t>(optionalHeaderOffset)) {
        std::cerr << "Error: Failed to get file header\n";
        return false;
    }

    const auto magic = *reinterpret_cast<const uint16_t*>(&rawData_[optionalHeaderOffset]);

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (!IsWithinBounds<IMAGE_NT_HEADERS32>(ntHeaderOffset)) {
            std::cerr << "32-bit NT header exceeds file range\n";
            return false;
        }
        ntHeaders32_ = *reinterpret_cast<const IMAGE_NT_HEADERS32*>(&rawData_[ntHeaderOffset]);
        peType_ = PE_TYPE::PE32;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (!IsWithinBounds<IMAGE_NT_HEADERS64>(ntHeaderOffset)) {
            std::cerr << "64-bit NT header exceeds file range\n";
            return false;
        }
        ntHeaders64_ = *reinterpret_cast<const IMAGE_NT_HEADERS64*>(&rawData_[ntHeaderOffset]);
        peType_ = PE_TYPE::PE64;
    } else {
        std::cerr << "Unknown optional header magic number: 0x" << std::hex << magic << "\n";
        return false;
    }

    // 提取节区头
    const IMAGE_FILE_HEADER* fileHeader = GetFileHeader();
    if (!fileHeader) {
        std::cerr << "Failed to get the file header\n";
        return false;
    }
    const size_t sectionOffset = ntHeaderOffset + sizeof(uint32_t) +
                                sizeof(IMAGE_FILE_HEADER) +
                                fileHeader->SizeOfOptionalHeader;
    const size_t sectionTableSize = fileHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER);

    if (!IsWithinBounds(sectionOffset, sectionTableSize)) {
        std::cerr << "Section table exceeds file range\n";
        return false;
    }

    sectionHeaders_.resize(fileHeader->NumberOfSections);
    std::memcpy(sectionHeaders_.data(), &rawData_[sectionOffset], sectionTableSize);

    rvaConverter_ = std::make_unique<RVAToOffsetConverter>(sectionHeaders_);
    isParsed_ = true;
    return true;
}

// 添加更多实用方法
std::optional<uint32_t> PEParser::GetEntryPoint() const {
    if (!isParsed_) return std::nullopt;

    switch (peType_) {
        case PE_TYPE::PE32:
            return ntHeaders32_.OptionalHeader.AddressOfEntryPoint;
        case PE_TYPE::PE64:
            return ntHeaders64_.OptionalHeader.AddressOfEntryPoint;
        default:
            return std::nullopt;
    }
}

std::optional<uint32_t> PEParser::GetImageBase() const {
    if (!isParsed_) return std::nullopt;

    switch (peType_) {
        case PE_TYPE::PE32:
            return ntHeaders32_.OptionalHeader.ImageBase;
        case PE_TYPE::PE64:
            // 64位ImageBase是uint64_t，但返回uint32_t可能丢失精度
            return static_cast<uint32_t>(ntHeaders64_.OptionalHeader.ImageBase);
        default:
            return std::nullopt;
    }
}

// 错误检查
PE_TYPE PEParser::GetPEType() const noexcept {
    return peType_;
}

const IMAGE_DOS_HEADER* PEParser::GetDOSHeader() const noexcept {
    return isParsed_ ? &dosHeader_ : nullptr;
}

const IMAGE_FILE_HEADER* PEParser::GetFileHeader() const noexcept {
    if (!isParsed_) return nullptr;

    if (peType_ == PE_TYPE::PE32) {
        return &ntHeaders32_.FileHeader;
    } else if (peType_ == PE_TYPE::PE64) {
        return &ntHeaders64_.FileHeader;
    }
    return nullptr;
}

const std::vector<IMAGE_SECTION_HEADER>& PEParser::GetSectionHeaders() const noexcept {
    return sectionHeaders_;
}

const std::vector<uint8_t>& PEParser::GetRawData() const noexcept {
    return rawData_;
}

uint32_t PEParser::RVAToOffset(uint32_t rva) const noexcept {
    return rvaConverter_ ? rvaConverter_->Convert(rva) : 0;
}
