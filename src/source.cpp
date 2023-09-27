#include "SMBCommand.h"

void LoopDumpDirectory(std::wstring a_wstring_directory) {
  std::wstring l_wstring_dir = a_wstring_directory + std::wstring(L"\\*.*");
  WIN32_FIND_DATA l_find_data = {0};
  HANDLE l_handle_find = FindFirstFile(l_wstring_dir.c_str(), &l_find_data);
  if (l_handle_find != INVALID_HANDLE_VALUE) {
    do {
      if (lstrcmpi(l_find_data.cFileName, L".") != 0 &&
          lstrcmpi(l_find_data.cFileName, L"..") != 0) {
        if ((l_find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
          std::wstring l_wstring_filepath = a_wstring_directory +
                                            std::wstring(L"\\") +
                                            std::wstring(l_find_data.cFileName);
          SMBCommand l_smbcommand_instance;
          l_smbcommand_instance.ParseFromFile(l_wstring_filepath.c_str());
          l_smbcommand_instance.DumpInfo();
        }
      }
    } while (FindNextFile(l_handle_find, &l_find_data));
  }
}

int main() {
  LoopDumpDirectory(L"D:\\shadowbroker_learning\\tran-data");
  /*SMBCommand l_smbcommand_instance;
  l_smbcommand_instance.ParseFromFile(
      L"D:\\shadowbroker_learning\\tran-data\\00000000_128_2021_09_10_12_20_57_"
      L"92_SMB1_1_NegotiateProtocolDialect");
  l_smbcommand_instance.DumpInfo();

  l_smbcommand_instance.ParseFromFile(
      L"D:\\shadowbroker_learning\\tran-data\\00000001_88_2021_09_10_12_20_57_"
      L"100");
  l_smbcommand_instance.DumpInfo();*/
}