#pragma once
#ifndef PE_PARSER_H
#define PE_PARSER_H

#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <optional>
#include "pe_structures.h"

class PEParser {
public:
    explicit PEParser(std::string filepath); // 使用值传递避免额外拷贝

    [[nodiscard]] bool Parse();
    [[nodiscard]] PE_TYPE GetPEType() const noexcept;
    [[nodiscard]] const IMAGE_DOS_HEADER* GetDOSHeader() const noexcept;
    [[nodiscard]] const IMAGE_FILE_HEADER* GetFileHeader() const noexcept;
    [[nodiscard]] const std::vector<IMAGE_SECTION_HEADER>& GetSectionHeaders() const noexcept;
    [[nodiscard]] const std::vector<uint8_t>& GetRawData() const noexcept;
    [[nodiscard]] uint32_t RVAToOffset(uint32_t rva) const noexcept;

    // 添加更多实用方法
    [[nodiscard]] std::optional<uint32_t> GetEntryPoint() const;
    [[nodiscard]] std::optional<uint32_t> GetImageBase() const;

private:
    std::string filepath_;
    std::vector<uint8_t> rawData_;

    bool isParsed_ = false;  // 添加解析状态标志
    IMAGE_DOS_HEADER dosHeader_{};
    PE_TYPE peType_ = PE_TYPE::UNKNOWN;

    union {
        IMAGE_NT_HEADERS32 ntHeaders32_{};
        IMAGE_NT_HEADERS64 ntHeaders64_;
    };

    std::vector<IMAGE_SECTION_HEADER> sectionHeaders_;
    std::unique_ptr<RVAToOffsetConverter> rvaConverter_;

    bool LoadFile();
    // bool ParseHeaders();

    // 添加边界检查方法
    template <typename T>
    [[nodiscard]] bool IsWithinBounds(size_t offset) const noexcept {
        return offset + sizeof(T) <= rawData_.size();
    }

    [[nodiscard]] bool IsWithinBounds(size_t offset, size_t size) const noexcept {
        return offset + size <= rawData_.size();
    }
};

#endif //PE_PARSER_H
