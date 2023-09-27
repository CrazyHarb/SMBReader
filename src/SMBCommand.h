#pragma once
#include "windows.h"
#include "SMBCommandType.h"

class SMBCommand {
 public:
  SMBCommand();
  ~SMBCommand();

  std::string FindDescByCommand(UCHAR a_uchar_command);
  void ParseCommand(unsigned char *a_ucharptr_buffer, ULONG a_ulong_bufferlen);
  void ParseFromFile(LPCWSTR a_lpcwstr_filePath);
  void DumpInfo();

private:
  unsigned char *m_ucharptr_buffer;
  ULONG m_ulong_bufferlen;
  std::wstring m_wstring_filePath;
};