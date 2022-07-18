#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include <windows.h>

namespace pescan {

using byte = std::uint8_t;

class PEImage {
 public:
  PEImage();
  PEImage(HANDLE hProcess);
  PEImage(const char* filepath);
  ~PEImage();

  void init(const void* data, size_t size);

  byte* data() const;
  size_t size() const;
  size_t base() const;

  byte* find(const std::vector<byte>& pattern,
             const std::vector<byte>& wildcard = {},
             size_t offset = 0,
             size_t limit = 0,
             bool up = false) const;
  std::vector<byte*> find_all(const std::vector<byte>& pattern,
                              const std::vector<byte>& wildcard = {},
                              size_t offset = 0,
                              size_t limit = 0,
                              bool up = false) const;

 private:
  std::vector<byte> buffer_;
  byte* data_;
  size_t size_;
  size_t base_;
};

}  // namespace investigate