#include "image.h"

#include <cassert>
#include <fstream>

#include <psapi.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

namespace pescan {

PEImage::PEImage() { 
  HMODULE hModule = ::GetModuleHandle(NULL); 

  BOOL ret;
  MODULEINFO modinfo{};
  ret = ::GetModuleInformation(::GetCurrentProcess(), hModule, &modinfo, sizeof(modinfo));
  assert(ret != 0);

  buffer_.resize(modinfo.SizeOfImage);
  ::memcpy(buffer_.data(), hModule, buffer_.size());

  init(buffer_.data(), buffer_.size());
}

PEImage::PEImage(HANDLE process) {
  ::WaitForInputIdle(process, INFINITE);

  DWORD process_id = ::GetProcessId(process);
  HANDLE handle = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                FALSE, process_id);
  assert(handle != NULL);

  BOOL ret;

  HMODULE mods[1024]{};
  DWORD needed;
  ret = ::EnumProcessModules(handle, mods, sizeof(mods), &needed);
  assert(ret == TRUE);

  MODULEINFO modinfo{};
  ret = ::GetModuleInformation(handle, mods[0], &modinfo, sizeof(modinfo));
  assert(ret != 0);

  DWORD size = modinfo.SizeOfImage;
  buffer_.resize(modinfo.SizeOfImage);
  ret = ::ReadProcessMemory(handle, modinfo.lpBaseOfDll, buffer_.data(), 2, NULL);
  assert(ret != 0);
  assert(buffer_[0] == 'M' && buffer_[1] == 'Z');

  ret = ::ReadProcessMemory(handle, mods[0], buffer_.data(), size, NULL);
  assert(ret != 0);

  ::CloseHandle(handle);

  init(buffer_.data(), buffer_.size());
}

PEImage::PEImage(const char* filepath) {
  std::ifstream ifs(filepath, std::ios::binary);
  buffer_ = std::vector<byte>((unsigned int)ifs.seekg(0, std::ios::end).tellg());
  ifs.seekg(0, std::ios::beg).read((char*)buffer_.data(), buffer_.size());

  init(buffer_.data(), buffer_.size());
}

void PEImage::init(const void* data, size_t size) {
  assert(size > 2);
  assert(((byte*)data)[0] == 'M' && ((byte*)data)[1] == 'Z');
  PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)data;
  PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((uint8_t*)data + dos_header->e_lfanew);
  data_ = (byte*)data;
  size_ = size;
  base_ = nt_headers->OptionalHeader.ImageBase;
}

PEImage::~PEImage() {}

byte* PEImage::data() const {
  return data_;
}

size_t PEImage::size() const {
  return size_;
}

size_t PEImage::base() const {
  return base_;
}

byte* PEImage::find(const std::vector<byte>& pattern,
                    const std::vector<byte>& wildcard,
                    size_t offset,
                    size_t limit,
                    bool up) const {
  assert(offset <= size_);

  if (limit == 0) {
    limit = up ? offset : (size_ - offset);
  }

  const byte* pattern_ptr = pattern.data();
  const byte* wildcard_ptr = wildcard.data();

  long pos = offset;
  for (long pos = offset, seq = 0; seq < limit; seq++, (!up ? pos++ : pos--)) {
    bool matched = true;
    for (size_t i = 0; i < pattern.size(); ++i) {
      if (i < wildcard.size() && wildcard_ptr[i] != 0x00) {
        continue;
      }

      if (data_[pos + i] != pattern[i]) {
        matched = false;
        break;
      }
    }

    if (matched) {
      return data_ + pos;
    }
  }
  return nullptr;
}

std::vector<byte*> PEImage::find_all(const std::vector<byte>& pattern,
                                     const std::vector<byte>& wildcard,
                                     size_t offset,
                                     size_t limit,
                                     bool up) const {
  std::vector<byte*> ret;
  while (true) {
    byte* next = find(pattern, wildcard, offset, limit, up);
    if (!next) {
      break;
    }

    ret.push_back(next);
    offset += (next - data_);
  }
  return ret;
}

}  // namespace investigate
