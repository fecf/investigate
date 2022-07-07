#include "image.h"

#include <cassert>
#include <fstream>

#include <psapi.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

namespace pescan {

PEImage::PEImage(const std::string& command_line,
                 const std::string& working_directory) {
  STARTUPINFOA si{};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi{};

  DWORD ret;
  ret = ::CreateProcessA(NULL, (char*)command_line.c_str(), NULL, NULL, FALSE,
                         0, 0, working_directory.c_str(), &si, &pi);
  assert(ret != 0);

  ret = ::WaitForInputIdle(pi.hProcess, 5000);
  assert(ret == 0);

  PROCESS_BASIC_INFORMATION pbi{};
  ULONG return_length;
  NTSTATUS status = ::NtQueryInformationProcess(
      pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &return_length);
  assert(status == 0);

  DWORD_PTR peb_offset = (DWORD_PTR)pbi.PebBaseAddress + 0x10;
  LPVOID image_base;
  ret = ::ReadProcessMemory(pi.hProcess, (LPVOID)peb_offset, &image_base, 16,
                            NULL);
  assert(ret == TRUE);

  BYTE headers[4096]{};
  ret = ::ReadProcessMemory(pi.hProcess, image_base, headers, 4096, NULL);
  assert(ret == TRUE);

  PIMAGE_NT_HEADERS32 nt_header = (PIMAGE_NT_HEADERS32)headers;

  data_ =
      reinterpret_cast<byte*>((uint64_t)nt_header->OptionalHeader.ImageBase);
  size_ = nt_header->OptionalHeader.SizeOfImage;
  init(data_, size_);
}

PEImage::PEImage(HANDLE hProcess, HMODULE hModule) {
  MODULEINFO modinfo{};
  BOOL ret =
      ::GetModuleInformation(hProcess, hModule, &modinfo, sizeof(modinfo));
  assert(ret == TRUE);

  data_ = (byte*)modinfo.EntryPoint;
  size_ = modinfo.SizeOfImage;
  init(data_, size_);
}

PEImage::PEImage(const void* data, uint64_t size) {
  data_ = (byte*)data;
  size_ = size;
  init(data_, size_);
}

PEImage::PEImage(const char* filepath) {
  std::ifstream ifs(filepath, std::ios::binary);
  buffer_ = std::vector<byte>(ifs.seekg(0, std::ios::end).tellg());
  ifs.seekg(0, std::ios::beg).read((char*)buffer_.data(), buffer_.size());
}

PEImage::~PEImage() {}

void PEImage::init(byte* data, uint64_t size) {
  PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)data;
  PIMAGE_NT_HEADERS nt_headers =
      (PIMAGE_NT_HEADERS)((uint8_t*)data + dos_header->e_lfanew);
  image_base_ = data_ + (nt_headers->OptionalHeader.ImageBase >> 32);
}

byte* PEImage::data() const {
  return data_;
}

uint64_t PEImage::size() const {
  return size_;
}

byte* PEImage::image_base() const {
  return image_base_;
}

byte* PEImage::find(const std::vector<byte>& pattern,
                    const std::vector<bool>& wildcard,
                    size_t offset,
                    size_t limit,
                    bool up) const {
  assert(offset <= size_);

  if (limit == 0) {
    limit = !up ? (size_ - offset) : offset;
  }

  size_t pos = offset;
  for (size_t pos = offset, seq = 0; seq < limit;
       seq++, (!up ? pos++ : pos--)) {
    bool matched = true;
    for (size_t i = 0; i < pattern.size(); ++i) {
      if (i < wildcard.size() && wildcard[i]) {
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
                                     const std::vector<bool>& wildcard,
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
