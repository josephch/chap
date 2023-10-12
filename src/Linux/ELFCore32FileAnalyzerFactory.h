// Copyright (c) 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: GPL-2.0

#pragma once

#include <cxxabi.h>

#include "../FileAnalyzerFactory.h"
#include "ELFCoreFileAnalyzer.h"

using namespace __cxxabiv1;

std::string util_demangle(std::string to_demangle) {
  int status = 0;
  char* buff =
      __cxxabiv1::__cxa_demangle(to_demangle.c_str(), NULL, NULL, &status);
  std::string demangled = buff;
  std::free(buff);
  return demangled;
}

namespace chap {
namespace Linux {
class ELFCore32FileAnalyzerFactory : public FileAnalyzerFactory {
 public:
  ELFCore32FileAnalyzerFactory()
      : FileAnalyzerFactory("32-bit little-endian ELF core file") {}

  /*
   * Make a FileAnalyzer to analyze the supported file type on the
   * given file, returning 0 if the file is not of the correct type.
   */

  virtual FileAnalyzer* MakeFileAnalyzer(const FileImage& fileImage,
                                         bool truncationCheckOnly) {
    try {
      return new ELFCoreFileAnalyzer<Elf32>(fileImage, truncationCheckOnly);
    } catch (std::bad_alloc&) {
      std::cerr << "There is not enough memory on this server to process"
                   " this ELF file.\n";
      exit(1);
    } catch (const std::exception& e) {
      std::cerr << e.what() << std::endl;
    } catch (chap::VirtualAddressMap<unsigned int>::NotMapped& ex) {
      std::cerr << "Exception: NotMapped. Address : " << std::hex << ex._address
                << std::dec << std::endl;
    } catch (...) {
      std::cerr << "\nUnknown exception type: '"
                << util_demangle(__cxa_current_exception_type()->name()) << "'"
                << std::endl;
    }
    return 0;
  }
};
}  // namespace Linux
}  // namespace chap
