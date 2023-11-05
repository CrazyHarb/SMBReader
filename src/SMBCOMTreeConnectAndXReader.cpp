#include "SMBCOMTreeConnectAndXReader.h"
#include "stdio.h"

SMBCOMTreeConnectAndXReader::SMBCOMTreeConnectAndXReader() {

}

SMBCOMTreeConnectAndXReader::~SMBCOMTreeConnectAndXReader() {

}

SMBCOMTreeConnectAndXReader* SMBCOMTreeConnectAndXReader::GetInstance() {
    static SMBCOMTreeConnectAndXReader g_smbcomtreeconnectandxreader_instance;
    return &g_smbcomtreeconnectandxreader_instance;
}

void SMBCOMTreeConnectAndXReader::DumpResponse(PSMB_HEADER a_psmb_header, PSMB_Parameters a_psmb_parameters, PSMB_Data a_psmb_data) {
    printf("Parameter->\r\n");

    //WordCount is *MUST* be 0x03 in msdn document, but here is 0x07
    //https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/3286744b-5b58-4ad5-b62e-c4f29a2492f1
    //I think it's wrong.

    if (a_psmb_parameters->WordCount == 0x07)
    {
        PSMB_Parameters_SMBCOMTreeConnectAndXResponse l_psmb_reponse = (PSMB_Parameters_SMBCOMTreeConnectAndXResponse)a_psmb_parameters;

        printf("    WordCount:%d\r\n", l_psmb_reponse->WordCount);
        printf("    AndXCommand:0x%02X\r\n", l_psmb_reponse->AndXCommand);
        printf("    AndXReserved:0x%02X\r\n", l_psmb_reponse->AndXReserved);
        printf("    AndXOffset:0x%04X\r\n", l_psmb_reponse->AndXOffset);
        printf("    OptionalSupport:0x%04X\r\n", l_psmb_reponse->OptionalSupport);

        printf("\r\n");

        printf("Data->\r\n");

        printf("    ByteCount: %d\r\n", a_psmb_data->ByteCount);

        UCHAR* l_uchar_dataBuffer = a_psmb_data->Bytes;
        UCHAR* l_uchar_dataBufferEnd = l_uchar_dataBuffer + a_psmb_data->ByteCount;

        printf("    Service: %s\r\n", (CHAR*)l_uchar_dataBuffer);
        l_uchar_dataBuffer += (lstrlenA((CHAR*)l_uchar_dataBuffer) + 1) * sizeof(CHAR);

        if (l_uchar_dataBuffer > l_uchar_dataBufferEnd)
        {
            printf("\r\n[error]data buffer out of range \r\n");
        }
        
        if (a_psmb_header->Flags2 & SMB_FLAGS2_UNICODE)
        {
            printf("    NativeFileSystem: %ws\r\n", (WCHAR*)l_uchar_dataBuffer);
            l_uchar_dataBuffer += (lstrlen((WCHAR*)l_uchar_dataBuffer) + 1) * sizeof(WCHAR);
        }
        else {
            printf("    NativeFileSystem: %s\r\n", (CHAR*)l_uchar_dataBuffer);
            l_uchar_dataBuffer += (lstrlenA((CHAR*)l_uchar_dataBuffer) + 1) * sizeof(CHAR);
        }

        if (l_uchar_dataBuffer > l_uchar_dataBufferEnd)
        {
            printf("\r\n[error]data buffer out of range \r\n");
        }

        printf("\r\n");
    }
}

void SMBCOMTreeConnectAndXReader::DumpRequest(PSMB_HEADER a_psmb_header, PSMB_Parameters a_psmb_parameters, PSMB_Data a_psmb_data) {
    printf("Parameter->\r\n");

    printf("    WordCount:%d\r\n", a_psmb_parameters->WordCount);

    PSMB_Parameters_SMBCOMTreeConnectAndXRequest l_psmb_currentParameters = (PSMB_Parameters_SMBCOMTreeConnectAndXRequest)a_psmb_parameters;

    //must be 0x0D
    if (a_psmb_parameters->WordCount != 0x4)
    {
        printf("WordCount error!\r\n");
    }
    else {
        printf("    AndXCommand:%d\r\n", l_psmb_currentParameters->AndXCommand);
        printf("    AndXReserved:%d\r\n", l_psmb_currentParameters->AndXReserved);
        printf("    AndXOffset:%d\r\n", l_psmb_currentParameters->AndXOffset);
        printf("    Flags:%d\r\n", l_psmb_currentParameters->Flags);
        printf("    PasswordLength:%d\r\n", l_psmb_currentParameters->PasswordLength);
    }
    printf("\r\n");

    printf("Data->\r\n");

    printf("    ByteCount:%d\r\n", a_psmb_data->ByteCount);
    if (a_psmb_data->ByteCount >= 0x3)
    {
        UCHAR* l_uchar_dataBuffer = a_psmb_data->Bytes;
        UCHAR* l_uchar_dataBufferEnd = l_uchar_dataBuffer + a_psmb_data->ByteCount;
        printf("    Password: ");
        for (size_t i = 0; i < l_psmb_currentParameters->PasswordLength; i++)
        {
            printf(" 0x%02X", *l_uchar_dataBuffer);
            l_uchar_dataBuffer++;
        }

        if (l_uchar_dataBuffer >= l_uchar_dataBufferEnd)
        {
            printf("\r\n[error]data buffer out of range \r\n");
        }

        //cuz GlobalAlloc return memory address start by :xxxx000, we only check the address.
        printf("\r\n    Pad: ");
        if (((ULONG_PTR)(l_uchar_dataBuffer - (unsigned char*)a_psmb_header) % 2) != 0)
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
            printf("    Path: %ws\r\n", (WCHAR*)l_uchar_dataBuffer);
            l_uchar_dataBuffer += (lstrlen((WCHAR*)l_uchar_dataBuffer) + 1) * sizeof(WCHAR);
        }
        else {
            printf("    Path: %s\r\n", (CHAR*)l_uchar_dataBuffer);
            l_uchar_dataBuffer += (lstrlenA((CHAR*)l_uchar_dataBuffer) + 1) * sizeof(CHAR);
        }

        if (l_uchar_dataBuffer >= l_uchar_dataBufferEnd)
        {
            printf("\r\n[error]data buffer out of range \r\n");
        }

        printf("    Service: %s\r\n", (CHAR*)l_uchar_dataBuffer);
        l_uchar_dataBuffer += (lstrlenA((CHAR*)l_uchar_dataBuffer) + 1) * sizeof(CHAR);

        if (l_uchar_dataBuffer > l_uchar_dataBufferEnd)
        {
            printf("\r\n[error]data buffer out of range \r\n");
        }
    }
    printf("\r\n");
}
