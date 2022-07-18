#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <vector>

#include "image.h"

namespace pescan {

class Cursor {
 public:
  Cursor() = delete;
  Cursor(const PEImage& image, byte* start, size_t size);
  ~Cursor();

  Cursor& find(const std::vector<byte>& pattern);
  Cursor& procedure_start();
  Cursor& left(size_t count, int offset = 0);
  Cursor& right(size_t count, int offset = 0);
  size_t offset() const;
  size_t size() const;

  template <typename T>
  T as() const {
    return *((T*)(start_));
  }
  uint32_t as_call_to() const {
    size_t base = offset();
    int32_t offset = *(int32_t*)(start_ + 1);
    return (uint32_t)(base + offset + 0x05);
  }

 private:
  const PEImage& image_;
  byte* start_;
  size_t size_;
};

class PatternFinder {
 public:
  PatternFinder() = delete;
  PatternFinder(const PEImage& image);
  ~PatternFinder();

  PatternFinder& find(const std::string& string);
  PatternFinder& find_all(const std::string& string);

  Cursor at(int n) const;
  Cursor single() const;
  Cursor first() const;
  Cursor last() const;

 private:
  std::pair<std::vector<byte>, std::vector<byte>> decode(
      const std::string& string);

 private:
  const PEImage& image_;
  std::vector<std::span<byte>> elements_;
};

}  // namespace pescan
