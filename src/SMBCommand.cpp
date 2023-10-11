#include "SMBCommand.h"
#include "NegotiateReader.h"
#include "SessionSetupAndXReader.h"

#include "stdio.h"


SMBCommand::SMBCommand() {
  m_ucharptr_buffer = 0;
  m_ulong_bufferlen = 0;
}

SMBCommand::~SMBCommand() {
  if (m_ucharptr_buffer != 0) {
    GlobalFree(m_ucharptr_buffer);
  }
}

std::string SMBCommand::FindDescByCommand(UCHAR a_uchar_command) {
  for (size_t i = 0;
       i < sizeof(g_array_smbCommand) / sizeof(*g_array_smbCommand); i++) {
    if (g_array_smbCommand[i].m_uchar_command == a_uchar_command) {
      return g_array_smbCommand[i].m_string_description;
    }
  }

  if (a_uchar_command >= 0x60 && a_uchar_command <= 0x6F) {
    return "Reserved";
  } else {
    return "Unused";
  }
}

void SMBCommand::ParseCommand(unsigned char *a_ucharptr_buffer,
                              ULONG a_ulong_bufferlen) {
  m_ulong_bufferlen = a_ulong_bufferlen;
  m_ucharptr_buffer = (unsigned char *)GlobalAlloc(GPTR, a_ulong_bufferlen);
  if (m_ucharptr_buffer) {
    RtlCopyMemory(m_ucharptr_buffer, a_ucharptr_buffer, a_ulong_bufferlen);
  }
}

ULONG convertBigEndianToLittleEndian(ULONG value) {
  ULONG result = 0;

  result |= ((value & 0xFF000000) >> 24);
  result |= ((value & 0x00FF0000) >> 8);
  result |= ((value & 0x0000FF00) << 8);
  result |= ((value & 0x000000FF) << 24);

  return result;
}

void SMBCommand::ParseFromFile(LPCWSTR a_lpcwstr_filePath) {
  m_wstring_filePath = a_lpcwstr_filePath;
  HANDLE l_handle_file =
      CreateFile(a_lpcwstr_filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

  if (l_handle_file != INVALID_HANDLE_VALUE) {
    DWORD l_dword_readCount = 0;
    DWORD l_dword_contentLen = 0;
    if (ReadFile(l_handle_file, &l_dword_contentLen, sizeof(l_dword_contentLen),
                 &l_dword_readCount, NULL) &&
        l_dword_readCount == sizeof(l_dword_contentLen)) {
      l_dword_contentLen = convertBigEndianToLittleEndian(l_dword_contentLen);
      m_ulong_bufferlen = l_dword_contentLen;
      m_ucharptr_buffer =
          (unsigned char *)GlobalAlloc(GPTR, l_dword_contentLen);
      if (m_ucharptr_buffer) {
        ReadFile(l_handle_file, m_ucharptr_buffer, m_ulong_bufferlen,
                 &l_dword_readCount, 0);
      }
    }

    CloseHandle(l_handle_file);
  }
}

void DumpParamter(unsigned char *a_ucharptr_buffer,ULONG a_ulong_bufferlen, unsigned char a_uchar_command, PSMB_HEADER a_psmb_header) {
    if (a_ucharptr_buffer)
    {
        PSMB_Parameters l_smbparemterptr_instance = (PSMB_Parameters)a_ucharptr_buffer;
        ULONG totalParamterLen = l_smbparemterptr_instance->WordCount * sizeof(USHORT) + sizeof(UCHAR);
        if (a_ulong_bufferlen >= totalParamterLen)
        {
            PSMB_Data l_smbdataptr_instance = (PSMB_Data)(a_ucharptr_buffer + totalParamterLen);
            ULONG totalDataLen = l_smbdataptr_instance->ByteCount * sizeof(UCHAR) + sizeof(USHORT);
            if (a_ulong_bufferlen >= (totalParamterLen + totalDataLen))
            {
                if (a_uchar_command == SMB_COM_NEGOTIATE)
                {
                    if (a_psmb_header->Flags & SMB_FLAGS_REPLY)
                    {
                        NegotiateReader::GetInstance()->DumpResponse(l_smbparemterptr_instance, l_smbdataptr_instance);
                    }
                    else {
                        NegotiateReader::GetInstance()->DumpRequest(l_smbparemterptr_instance, l_smbdataptr_instance);
                    }
                }
                else if (a_uchar_command == SMB_COM_SESSION_SETUP_ANDX)
                {
                    if (a_psmb_header->Flags & SMB_FLAGS_REPLY)
                    {

                    }
                    else {
                        SessionSetupAndXReader::GetInstance()->DumpRequest(l_smbparemterptr_instance, l_smbdataptr_instance);
                    }
                }
            }
        }
    }

}

void SMBCommand::DumpInfo() {
  printf("========================DUMP %ws START========================\n",
         m_wstring_filePath.c_str());
  if (m_ucharptr_buffer && m_ulong_bufferlen >= sizeof(SMB_HEADER)) {
    PSMB_HEADER l_smb_header = (PSMB_HEADER)m_ucharptr_buffer;
    printf("[Protocol]0x%02x %c %c %c \n", l_smb_header->Protocol[0],
           l_smb_header->Protocol[1], l_smb_header->Protocol[2],
           l_smb_header->Protocol[3]);
    printf("[Command]0x%02x: %s \n", l_smb_header->Command,
           FindDescByCommand(l_smb_header->Command).c_str());

    printf("[Status]0x%08x \n", l_smb_header->Status);

    printf("[Flags]0x%02x \n", l_smb_header->Flags);
    printf("[Flags2]0x%04x \n", l_smb_header->Flags2);
    printf("[PIDHigh]0x%04x \n", l_smb_header->PIDHigh);
    printf(
        "[SecurityFeatures]0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x "
        "0x%02x \n",
        l_smb_header->SecurityFeatures[0], l_smb_header->SecurityFeatures[1],
        l_smb_header->SecurityFeatures[2], l_smb_header->SecurityFeatures[3],
        l_smb_header->SecurityFeatures[4], l_smb_header->SecurityFeatures[5],
        l_smb_header->SecurityFeatures[6], l_smb_header->SecurityFeatures[7]);

    printf("[Reserved]0x%04x \n", l_smb_header->Reserved);
    printf("[TID]0x%04x \n", l_smb_header->TID);
    printf("[PIDLow]0x%04x \n", l_smb_header->PIDLow);
    printf("[UID]0x%04x \n", l_smb_header->UID);
    printf("[MID]0x%04x \n", l_smb_header->MID);

    DumpParamter(m_ucharptr_buffer + sizeof(SMB_HEADER), m_ulong_bufferlen - sizeof(SMB_HEADER), l_smb_header->Command, l_smb_header);
  } else {
    printf("Header len error!\n");
  }
  printf("========================DUMP %ws END========================\n",
         m_wstring_filePath.c_str());
}
