#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include <windows.h>

namespace pescan {

using byte = std::byte;

class PEImage {
 public:
  PEImage(const std::string& command_line,
          const std::string& working_directory);
  PEImage(HANDLE hProcess, HMODULE hModule);
  PEImage(const void* data, uint64_t size);
  PEImage(const char* filepath);
  ~PEImage();

  void init(byte* data, uint64_t size);
  byte* data() const;
  size_t size() const;
  byte* image_base() const;

  byte* find(const std::vector<byte>& pattern,
             const std::vector<bool>& wildcard = {},
             size_t offset = 0,
             size_t limit = 0,
             bool up = false) const;
  std::vector<byte*> find_all(const std::vector<byte>& pattern,
                              const std::vector<bool>& wildcard = {},
                              size_t offset = 0,
                              size_t limit = 0,
                              bool up = false) const;

 private:
  std::vector<byte> buffer_;
  byte* data_;
  size_t size_;

  byte* image_base_;
};

}  // namespace investigate