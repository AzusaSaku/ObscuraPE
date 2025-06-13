cmake_minimum_required(VERSION 3.30)
project(ObscuraPE)

set(CMAKE_CXX_STANDARD 20)

add_executable(ObscuraPE main.cpp
        PE-Parser/pe_structures.h
        PE-Parser/pe_parser.h
        PE-Parser/pe_parser.cpp
        Packer-Core/packer.cpp
        Packer-Core/packer.h
        Packer-Core/section_builder.h
        Stub-Generator/stub_generator.cpp
        Stub-Generator/stub_generator.h
        Resource-Manager/resource-manager.cpp
        Resource-Manager/resource-manager.h
        Crypto/crypto.cpp
        Crypto/crypto.h
)
