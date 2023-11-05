#include "SessionSetupAndXReader.h"
#include "stdio.h"

SessionSetupAndXReader::SessionSetupAndXReader() {

}

SessionSetupAndXReader::~SessionSetupAndXReader() {

}

SessionSetupAndXReader* SessionSetupAndXReader::GetInstance() {
    static SessionSetupAndXReader g_sessionsetupandxreader_instance;
    return &g_sessionsetupandxreader_instance;
}

void SessionSetupAndXReader::DumpResponse(PSMB_HEADER a_psmb_header, PSMB_Parameters a_psmb_parameters, PSMB_Data a_psmb_data) {
    printf("Parameter->\r\n");
    if (a_psmb_parameters->WordCount == 0x03)
    {
        PSMB_Parameters_SessionSetupAndXResponse l_psmb_reponse = (PSMB_Parameters_SessionSetupAndXResponse)a_psmb_parameters;

        printf("    WordCount:%d\r\n", l_psmb_reponse->WordCount);
        printf("    AndXCommand:0x%02X\r\n", l_psmb_reponse->AndXCommand);
        printf("    AndXReserved:0x%02X\r\n", l_psmb_reponse->AndXReserved);
        printf("    AndXOffset:0x%04X\r\n", l_psmb_reponse->AndXOffset);
        printf("    Action:0x%04X\r\n", l_psmb_reponse->Action);

        printf("\r\n");

        printf("Data->\r\n");

        PSMB_Data_NTLANManager_response l_psmbdata_reponse = (PSMB_Data_NTLANManager_response)a_psmb_data;
        UCHAR* l_uchar_dataBuffer = a_psmb_data->Bytes;
        UCHAR* l_uchar_dataBufferEnd = l_uchar_dataBuffer + a_psmb_data->ByteCount;

        printf("    Pad: ");
        if (((ULONG_PTR)(l_uchar_dataBuffer - (unsigned char*)a_psmb_header) % 2) != 0)
        {
            printf(" 0x%02X", *l_uchar_dataBuffer);
            l_uchar_dataBuffer++;
            l_uchar_dataBufferEnd++;
        }

        printf("\r\n");
        
        if (a_psmb_header->Flags2 & SMB_FLAGS2_UNICODE)
        {
            printf("    NativeOS: %ws\r\n", (WCHAR*)l_uchar_dataBuffer);
            l_uchar_dataBuffer += (lstrlen((WCHAR*)l_uchar_dataBuffer) + 1) * sizeof(WCHAR);
        }
        else {
            printf("    NativeOS: %s\r\n", (CHAR*)l_uchar_dataBuffer);
            l_uchar_dataBuffer += (lstrlenA((CHAR*)l_uchar_dataBuffer) + 1) * sizeof(CHAR);
        }
       
        if (l_uchar_dataBuffer >= l_uchar_dataBufferEnd)
        {
            printf("\r\n[error]data buffer out of range \r\n");
        }

        if (a_psmb_header->Flags2 & SMB_FLAGS2_UNICODE)
        {
            printf("    NativeLanMan: %ws\r\n", (WCHAR*)l_uchar_dataBuffer);
            l_uchar_dataBuffer += (lstrlen((WCHAR*)l_uchar_dataBuffer) + 1) * sizeof(WCHAR);
        }
        else {
            printf("    NativeLanMan: %s\r\n", (CHAR*)l_uchar_dataBuffer);
            l_uchar_dataBuffer += (lstrlenA((CHAR*)l_uchar_dataBuffer) + 1) * sizeof(CHAR);
        }

        if (l_uchar_dataBuffer >= l_uchar_dataBufferEnd)
        {
            printf("\r\n[error]data buffer out of range \r\n");
        }

        if (a_psmb_header->Flags2 & SMB_FLAGS2_UNICODE)
        {
            printf("    PrimaryDomain: %ws\r\n", (WCHAR*)l_uchar_dataBuffer);
            l_uchar_dataBuffer += (lstrlen((WCHAR*)l_uchar_dataBuffer) + 1) * sizeof(WCHAR);
        }
        else {
            printf("    PrimaryDomain: %s\r\n", (CHAR*)l_uchar_dataBuffer);
            l_uchar_dataBuffer += (lstrlenA((CHAR*)l_uchar_dataBuffer) + 1) * sizeof(CHAR);
        }

        if (l_uchar_dataBuffer != l_uchar_dataBufferEnd)
        {
            printf("[ERROR]buffer end is not equal current buffer pointer\r\n");
        }
       
        printf("\r\n");
    }
}

void SessionSetupAndXReader::DumpRequest(PSMB_HEADER a_psmb_header, PSMB_Parameters a_psmb_parameters, PSMB_Data a_psmb_data) {
    printf("Parameter->\r\n");

    printf("    WordCount:%d\r\n", a_psmb_parameters->WordCount);

    PSMB_Parameters_SessionSetupAndX l_psmb_currentParameters = (PSMB_Parameters_SessionSetupAndX)a_psmb_parameters;

    //must be 0x0D
    if (a_psmb_parameters->WordCount != 0xD)
    {
        printf("WordCount error!\r\n");
    }
    else {
        printf("    AndXCommand:%d\r\n", l_psmb_currentParameters->AndXCommand);
        printf("    AndXReserved:%d\r\n", l_psmb_currentParameters->AndXReserved);
        printf("    AndXOffset:%d\r\n", l_psmb_currentParameters->AndXOffset);
        printf("    MaxBufferSize:%d\r\n", l_psmb_currentParameters->MaxBufferSize);
        printf("    MaxMpxCount:%d\r\n", l_psmb_currentParameters->MaxMpxCount);
        printf("    VcNumber:%d\r\n", l_psmb_currentParameters->VcNumber);
        printf("    SessionKey:%d\r\n", l_psmb_currentParameters->SessionKey);
        printf("    OEMPasswordLen:%d\r\n", l_psmb_currentParameters->OEMPasswordLen);
        printf("    UnicodePasswordLen:%d\r\n", l_psmb_currentParameters->UnicodePasswordLen);
        printf("    Reserved:%d\r\n", l_psmb_currentParameters->Reserved);
        printf("    Capabilities:0x%X\r\n", l_psmb_currentParameters->Capabilities);
    }
    printf("\r\n");

    printf("Data->\r\n");

    printf("    ByteCount:%d\r\n", a_psmb_data->ByteCount);
    if (a_psmb_data->ByteCount >= 0x2)
    {
        UCHAR *l_uchar_dataBuffer = a_psmb_data->Bytes;
        UCHAR* l_uchar_dataBufferEnd = l_uchar_dataBuffer + a_psmb_data->ByteCount;
        printf("    OEMPassword: ");
        for (size_t i = 0; i < l_psmb_currentParameters->OEMPasswordLen; i++)
        {
            printf(" 0x%02X", *l_uchar_dataBuffer);
            l_uchar_dataBuffer++;
        }

        if (l_uchar_dataBuffer >= l_uchar_dataBufferEnd)
        {
            printf("\r\n[error]data buffer out of range \r\n");
        }

        printf("\r\n    UnicodePassword: ");
        for (size_t i = 0; i < l_psmb_currentParameters->UnicodePasswordLen; i++)
        {
            printf(" 0x%04X", *(USHORT *)l_uchar_dataBuffer);
            l_uchar_dataBuffer += 2;
        }

        if (l_uchar_dataBuffer >= l_uchar_dataBufferEnd)
        {
            printf("\r\n[error]data buffer out of range \r\n");
        }

        //cuz GlobalAlloc return memory address start by :xxxx000, we only check the address.
        printf("\r\n    Pad: ");
        if (((ULONG_PTR)(l_uchar_dataBuffer - (unsigned char *)a_psmb_header) % 2) !=0)
        {
            printf(" 0x00");
            l_uchar_dataBuffer++;
        }
        printf("\r\n");

        if (l_uchar_dataBuffer >= l_uchar_dataBufferEnd)
        {
            printf("\r\n[error]data buffer out of range \r\n");
        }

        if (a_psmb_header->Flags2 & SMB_FLAGS2_UNICODE)
        {
            printf("    AccountName: %ws\r\n", (WCHAR*)l_uchar_dataBuffer);
            l_uchar_dataBuffer += (lstrlen((WCHAR*)l_uchar_dataBuffer) + 1) * sizeof(WCHAR);
        }
        else {
            printf("    AccountName: %s\r\n", (CHAR*)l_uchar_dataBuffer);
            l_uchar_dataBuffer += (lstrlenA((CHAR*)l_uchar_dataBuffer) + 1) * sizeof(CHAR);
        }

        if (l_uchar_dataBuffer >= l_uchar_dataBufferEnd)
        {
            printf("\r\n[error]data buffer out of range \r\n");
        }

        if (a_psmb_header->Flags2 & SMB_FLAGS2_UNICODE)
        {
            printf("    PrimaryDomain: %ws\r\n", (WCHAR*)l_uchar_dataBuffer);
            l_uchar_dataBuffer += (lstrlen((WCHAR*)l_uchar_dataBuffer) + 1) * sizeof(WCHAR);
        }
        else {
            printf("    PrimaryDomain: %s\r\n", (CHAR*)l_uchar_dataBuffer);
            l_uchar_dataBuffer += (lstrlenA((CHAR*)l_uchar_dataBuffer) + 1) * sizeof(CHAR);
        }

        if (l_uchar_dataBuffer >= l_uchar_dataBufferEnd)
        {
            printf("\r\n[error]data buffer out of range \r\n");
        }

        if (a_psmb_header->Flags2 & SMB_FLAGS2_UNICODE)
        {
            printf("    NativeOS: %ws\r\n", (WCHAR*)l_uchar_dataBuffer);
            l_uchar_dataBuffer += (lstrlen((WCHAR*)l_uchar_dataBuffer) + 1) * sizeof(WCHAR);
        }
        else {
            printf("    NativeOS: %s\r\n", (CHAR*)l_uchar_dataBuffer);
            l_uchar_dataBuffer += (lstrlenA((CHAR*)l_uchar_dataBuffer) + 1) * sizeof(CHAR);
        }

        if (l_uchar_dataBuffer >= l_uchar_dataBufferEnd)
        {
            printf("\r\n[error]data buffer out of range \r\n");
        }

        if (a_psmb_header->Flags2 & SMB_FLAGS2_UNICODE)
        {
            printf("    NativeLanMan: %ws\r\n", (WCHAR*)l_uchar_dataBuffer);
            l_uchar_dataBuffer += (lstrlen((WCHAR*)l_uchar_dataBuffer) + 1) * sizeof(WCHAR);
        }
        else {
            printf("    NativeLanMan: %s\r\n", (CHAR*)l_uchar_dataBuffer);
            l_uchar_dataBuffer += (lstrlenA((CHAR*)l_uchar_dataBuffer) + 1) * sizeof(CHAR);
        }

        if (l_uchar_dataBuffer != l_uchar_dataBufferEnd)
        {
            printf("[ERROR]buffer end is not equal current buffer pointer\r\n");
        }

        //printf("        BufferFormat:0x%02x\r\n", l_psmb_dialect->BufferFormat);

        //std::string l_string_instance((const char*)l_psmb_dialect->DialectString, a_psmb_data->ByteCount - sizeof(USHORT) - sizeof(UCHAR));
        //printf("        DialectString:%s\r\n", l_string_instance.c_str());
    }
    printf("\r\n");
}