#include "pescan.h"

#include <cassert>
#include <stdexcept>
#include <regex>

namespace pescan {

template <typename... ts>
std::vector<std::byte> make_bytes(ts&&... args) noexcept {
  return {std::byte(std::forward<ts>(args))...};
}

Cursor::Cursor(const PEImage& image, byte* start, size_t size) 
    : image_(image), start_(start), size_(size) {
  assert(start_ >= image.data());
  assert((start_ + size_) < (image.data() + image.size()));
}

Cursor::~Cursor() {}

size_t Cursor::offset() const {
  size_t offset = image_.image_base() - image_.data();
  return start_ - image_.data() + offset;
}

size_t Cursor::size() const {
  return size_;
}

Cursor PatternFinder::at(int n) const {
  if (n < 0 || n >= elements_.size()) {
    throw std::runtime_error("out of range.");
  }
  return Cursor(image_, elements_[n].data(), elements_[n].size());
}

Cursor PatternFinder::single() const {
  if (elements_.size() != 1) {
    throw std::runtime_error("size != 1");
  }
  return Cursor(image_, elements_[0].data(), elements_[0].size());
}

Cursor PatternFinder::first() const {
  if (elements_.empty()) {
    throw std::runtime_error("out of range.");
  }
  return Cursor(image_, elements_[0].data(), elements_[0].size());
}

Cursor PatternFinder::last() const {
  if (elements_.empty()) {
    throw std::runtime_error("out of range.");
  }
  return Cursor(image_, elements_.back().data(), elements_.back().size());
}

Cursor& Cursor::find(const std::vector<byte>& pattern) {
  byte* result = image_.find(pattern);
  if (!result) {
    throw std::runtime_error("not found.");
  }
  int64_t shrink = result - start_;
  start_ = result;
  size_ -= shrink;
  return *this;
}

Cursor& Cursor::procedure_start() {
  byte* result = image_.find(make_bytes(0x55, 0x8b, 0xec), {}, start_ - image_.data(), 0, true);
  if (!result) {
    throw std::runtime_error("not found.");
  }
  int64_t grow = start_ - result;
  start_ = result;
  size_ += grow;
  return *this;
}

Cursor& Cursor::left(size_t count, int offset) {
  start_ += offset;
  size_ = count;
  return *this;
}

Cursor& Cursor::right(size_t count, int offset) {
  start_ = start_ + size_ - count;
  size_ = count;
  return *this;
}

PatternFinder::PatternFinder(const PEImage& image) : image_(image) {}

PatternFinder::~PatternFinder() {}

PatternFinder& PatternFinder::find(const std::string& string) {
  const auto [pattern, wildcard] = decode(string);

  elements_.clear();
  byte* ret = image_.find(pattern, wildcard);
  if (ret) {
    elements_.push_back({ret, pattern.size()});
  }

  return *this;
}

PatternFinder& PatternFinder::find_all(const std::string& string) {
  const auto [pattern, wildcard] = decode(string);

  elements_.clear();
  std::vector<byte*> ret = image_.find_all(pattern, wildcard);
  for (byte* ptr : ret) {
    elements_.push_back({ptr, pattern.size()});
  }

  return *this;
}

std::pair<std::vector<byte>, std::vector<bool>> PatternFinder::decode(
    const std::string& string) {
  std::regex re("[ \t]");
  std::string sanitized = std::regex_replace(string, re, "");

  std::vector<byte> pattern;
  std::vector<bool> wildcard;

  uint64_t bytes_size = sanitized.size() / 2;
  pattern.resize(bytes_size, (byte)0x0);
  wildcard.resize(bytes_size, false);

  const char* ptr = sanitized.c_str();
  for (uint64_t i = 0; i < bytes_size; i++) {
    if (sanitized[i * 2] == '?') {
      if (sanitized[i * 2 + 1] == '?') {
        wildcard[i] = true;
      } else {
        throw std::runtime_error("unexpected token");
      }
    } else {
      std::string token(sanitized, i * 2, 2);
      long ret = strtol(token.data(), NULL, 16);
      pattern[i] = (byte)ret;
    }
  }

  return { pattern, wildcard };
}

}  // namespace investigate