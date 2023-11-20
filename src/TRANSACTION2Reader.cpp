#include "Transaction2Reader.h"
#include "stdio.h"

SMBCOMTranscation2Reader::SMBCOMTranscation2Reader() {

}

SMBCOMTranscation2Reader::~SMBCOMTranscation2Reader() {

}

SMBCOMTranscation2Reader* SMBCOMTranscation2Reader::GetInstance() {
    static SMBCOMTranscation2Reader g_smbcomtranscation2_instance;
    return &g_smbcomtranscation2_instance;
}

void SMBCOMTranscation2Reader::DumpResponse(PSMB_HEADER a_psmb_header, PSMB_Parameters a_psmb_parameters, PSMB_Data a_psmb_data) {
    printf("Parameter->\r\n");

    printf("    WordCount:%d\r\n", a_psmb_parameters->WordCount);

    PSMB_Parameters_SMBCOMTranscation2Response l_psmb_currentParameters = (PSMB_Parameters_SMBCOMTranscation2Response)a_psmb_parameters;

    //must be 0x0
    if (a_psmb_parameters->WordCount == 0)
    {
        //printf("WordCount error!\r\n");
    }
    else {
        printf("    TotalParameterCount:%d\r\n", l_psmb_currentParameters->TotalParameterCount);
        printf("    TotalDataCount:%d\r\n", l_psmb_currentParameters->TotalDataCount);
        printf("    Reserved1:0x%02x\r\n", l_psmb_currentParameters->Reserved1);
        printf("    ParameterCount:%d\r\n", l_psmb_currentParameters->ParameterCount);
        printf("    ParameterOffset:%d\r\n", l_psmb_currentParameters->ParameterOffset);
        printf("    ParameterDisplacement:%d\r\n", l_psmb_currentParameters->ParameterDisplacement);
        printf("    DataCount:%d\r\n", l_psmb_currentParameters->DataCount);
        printf("    DataOffset:%d\r\n", l_psmb_currentParameters->DataOffset);
        printf("    DataDisplacement:%d\r\n", l_psmb_currentParameters->DataDisplacement);
        printf("    SetupCount:%d\r\n", l_psmb_currentParameters->SetupCount);
        printf("    Reserved2:%d\r\n", l_psmb_currentParameters->Reserved2);

        printf("    Setup:");
        for (size_t i = 0; i < l_psmb_currentParameters->SetupCount; i++)
        {
            printf(" 0x%02X", l_psmb_currentParameters->Setup[i]);
        }
        printf("\r\n");
    }
    printf("\r\n");

    printf("Data->\r\n");

    printf("    ByteCount:%d\r\n", a_psmb_data->ByteCount);
    //must be 0x0
    if (a_psmb_data->ByteCount > 0)
    {
        UCHAR* l_uchar_dataBuffer = a_psmb_data->Bytes;
        UCHAR* l_uchar_dataBufferEnd = l_uchar_dataBuffer + a_psmb_data->ByteCount;
        printf("    Name: 0x%02X", *l_uchar_dataBuffer);
        l_uchar_dataBuffer++;

        if (l_uchar_dataBuffer > l_uchar_dataBufferEnd)
        {
            printf("\r\n[error]data buffer out of range \r\n");
        }

        //cuz GlobalAlloc return memory address start by :xxxx000, we only check the address.
        printf("\r\n    Pad1: ");
        if (((ULONG_PTR)(l_uchar_dataBuffer - (unsigned char*)a_psmb_header) % 4) != 0)
        {
            ULONG_PTR l_ulong_padlen = (4 - (ULONG_PTR)(l_uchar_dataBuffer - (unsigned char*)a_psmb_header) % 4);
            for (size_t i = 0; i < l_ulong_padlen; i++)
            {
                printf(" 0x00");
                l_uchar_dataBuffer++;
            }
        }
        printf("\r\n    Trans2_Parameters:");
        for (size_t i = 0; i < l_psmb_currentParameters->ParameterCount; i++)
        {
            printf(" %02X", *l_uchar_dataBuffer);
            l_uchar_dataBuffer++;
        }

        if (l_uchar_dataBuffer > l_uchar_dataBufferEnd)
        {
            printf("\r\n[error]data buffer out of range \r\n");
        }

        printf("\r\n    Pad2: ");
        if (((ULONG_PTR)(l_uchar_dataBuffer - (unsigned char*)a_psmb_header) % 4) != 0)
        {
            ULONG_PTR l_ulong_padlen = (ULONG_PTR)(l_uchar_dataBuffer - (unsigned char*)a_psmb_header) % 4;
            for (size_t i = 0; i < l_ulong_padlen; i++)
            {
                printf(" 0x00");
                l_uchar_dataBuffer++;
            }
        }

        if (l_uchar_dataBuffer > l_uchar_dataBufferEnd)
        {
            printf("\r\n[error]data buffer out of range \r\n");
        }

        printf("\r\n    Trans2_Data:");
        for (size_t i = 0; i < l_psmb_currentParameters->DataCount; i++)
        {
            printf(" %02X", *l_uchar_dataBuffer);
            l_uchar_dataBuffer++;
        }

        if (l_uchar_dataBuffer > l_uchar_dataBufferEnd)
        {
            printf("\r\n[error]data buffer out of range \r\n");
        }
    }
    printf("\r\n");
}

void SMBCOMTranscation2Reader::DumpRequest(PSMB_HEADER a_psmb_header, PSMB_Parameters a_psmb_parameters, PSMB_Data a_psmb_data) {
    printf("Parameter->\r\n");

    printf("    WordCount:%d\r\n", a_psmb_parameters->WordCount);

    PSMB_Parameters_SMBCOMTranscation2Request l_psmb_currentParameters = (PSMB_Parameters_SMBCOMTranscation2Request)a_psmb_parameters;

    //must be 0x0D
    if (a_psmb_parameters->WordCount < 0xE)
    {
        printf("WordCount error!\r\n");
    }
    else {
        printf("    TotalParameterCount:%d\r\n", l_psmb_currentParameters->TotalParameterCount);
        printf("    TotalDataCount:%d\r\n", l_psmb_currentParameters->TotalDataCount);
        printf("    MaxParameterCount:%d\r\n", l_psmb_currentParameters->MaxParameterCount);
        printf("    MaxDataCount:%d\r\n", l_psmb_currentParameters->MaxDataCount);
        printf("    MaxSetupCount:%d\r\n", l_psmb_currentParameters->MaxSetupCount);
        printf("    Reserved1:0x%02x\r\n", l_psmb_currentParameters->Reserved1);
        printf("    Flags:%d\r\n", l_psmb_currentParameters->Flags);
        printf("    Timeout:%d\r\n", l_psmb_currentParameters->Timeout);
        printf("    Reserved2:0x%02x\r\n", l_psmb_currentParameters->Reserved2);
        printf("    ParameterCount:%d\r\n", l_psmb_currentParameters->ParameterCount);
        printf("    ParameterOffset:%d\r\n", l_psmb_currentParameters->ParameterOffset);
        printf("    DataCount:%d\r\n", l_psmb_currentParameters->DataCount);
        printf("    DataOffset:%d\r\n", l_psmb_currentParameters->DataOffset);
        printf("    SetupCount:%d\r\n", l_psmb_currentParameters->SetupCount);
        printf("    Reserved3:%d\r\n", l_psmb_currentParameters->Reserved3);

        printf("    Setup:");
        for (size_t i = 0; i < l_psmb_currentParameters->SetupCount; i++)
        {
            printf(" 0x%02X", l_psmb_currentParameters->Setup[i]);
        }
        printf("\r\n");
    }
    printf("\r\n");

    printf("Data->\r\n");

    printf("    ByteCount:%d\r\n", a_psmb_data->ByteCount);
    if (a_psmb_data->ByteCount >= 0x3)
    {
        UCHAR* l_uchar_dataBuffer = a_psmb_data->Bytes;
        UCHAR* l_uchar_dataBufferEnd = l_uchar_dataBuffer + a_psmb_data->ByteCount;
        printf("    Name: 0x%02X", *l_uchar_dataBuffer);
        l_uchar_dataBuffer++;

        if (l_uchar_dataBuffer > l_uchar_dataBufferEnd)
        {
            printf("\r\n[error]data buffer out of range \r\n");
        }

        //cuz GlobalAlloc return memory address start by :xxxx000, we only check the address.
        printf("\r\n    Pad1: ");
        if (((ULONG_PTR)(l_uchar_dataBuffer - (unsigned char*)a_psmb_header) % 4) != 0)
        {
            ULONG_PTR l_ulong_padlen = (4 - (ULONG_PTR)(l_uchar_dataBuffer - (unsigned char*)a_psmb_header) % 4);
            for (size_t i = 0; i < l_ulong_padlen; i++)
            {
                printf(" 0x00");
                l_uchar_dataBuffer++;
            }
        }
        printf("\r\n    Trans2_Parameters:");
        for (size_t i = 0; i < l_psmb_currentParameters->ParameterCount; i++)
        {
            printf(" %02X", *l_uchar_dataBuffer);
            l_uchar_dataBuffer++;
        }

        if (l_uchar_dataBuffer > l_uchar_dataBufferEnd)
        {
            printf("\r\n[error]data buffer out of range \r\n");
        }

        printf("\r\n    Pad2: ");
        if (((ULONG_PTR)(l_uchar_dataBuffer - (unsigned char*)a_psmb_header) % 4) != 0)
        {
            ULONG_PTR l_ulong_padlen = (ULONG_PTR)(l_uchar_dataBuffer - (unsigned char*)a_psmb_header) % 4;
            for (size_t i = 0; i < l_ulong_padlen; i++)
            {
                printf(" 0x00");
                l_uchar_dataBuffer++;
            }
        }

        if (l_uchar_dataBuffer > l_uchar_dataBufferEnd)
        {
            printf("\r\n[error]data buffer out of range \r\n");
        }

        printf("\r\n    Trans2_Data:");
        for (size_t i = 0; i < l_psmb_currentParameters->DataCount; i++)
        {
            printf(" %02X", *l_uchar_dataBuffer);
            l_uchar_dataBuffer++;
        }

        if (l_uchar_dataBuffer > l_uchar_dataBufferEnd)
        {
            printf("\r\n[error]data buffer out of range \r\n");
        }
    }
    printf("\r\n");
}
