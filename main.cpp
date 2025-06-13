#include <iostream>

#include "PE-Parser/pe_parser.h"

int main() {
    PEParser parser(R"(D:\Clash.Verge_1.3.8_x64_portable\Clash Verge.exe)");
    if (parser.Parse()) {
        if (auto entryPoint = parser.GetEntryPoint()) {
            std::cout << "Entry point: 0x" << std::hex << *entryPoint << "\n";
        }

        if (const auto* dosHeader = parser.GetDOSHeader()) {
            std::cout << "DOS header signature: 0x" << std::hex << dosHeader->e_magic << "\n";
        }

        if (const auto* fileHeader = parser.GetFileHeader()) {
            std::cout << "Number of sections: " << std::dec << fileHeader->NumberOfSections << "\n";
        }

        for (const auto& section : parser.GetSectionHeaders()) {
            std::cout << "Section: " << PEUtils::SectionNameToString(section.Name) << "\n";
        }
    } else {
        std::cerr << "Failed to parse PE file\n";
    }

    return 0;
}
