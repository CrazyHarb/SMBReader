#include "NegotiateReader.h"
#include "stdio.h"

NegotiateReader::NegotiateReader() {

}

NegotiateReader::~NegotiateReader() {

}

NegotiateReader* NegotiateReader::GetInstance() {
	static NegotiateReader g_negotiatereader_instance;
	return &g_negotiatereader_instance;
}

void NegotiateReader::DumpResponse(PSMB_Parameters a_psmb_parameters, PSMB_Data a_psmb_data) {
    printf("Parameter->\r\n");
    if (a_psmb_parameters->WordCount == 0x11)
    {
        printf("    NT LAN Manager\r\n");
        PSMB_Parameters_NTLANManager_response l_psmb_reponse = (PSMB_Parameters_NTLANManager_response)a_psmb_parameters;

        printf("    WordCount:%d\r\n", l_psmb_reponse->WordCount);
        printf("    DialectIndex:0x%04X\r\n", l_psmb_reponse->DialectIndex);
        printf("    SecurityMode:0x%02X\r\n", l_psmb_reponse->SecurityMode);
        printf("    MaxMpxCount:0x%04X\r\n", l_psmb_reponse->MaxMpxCount);
        printf("    MaxNumberVcs:0x%04X\r\n", l_psmb_reponse->MaxNumberVcs);
        printf("    MaxBufferSize:0x%08X\r\n", l_psmb_reponse->MaxBufferSize);
        printf("    MaxRawSize:0x%08X\r\n", l_psmb_reponse->MaxRawSize);
        printf("    SessionKey:0x%08X\r\n", l_psmb_reponse->SessionKey);
        printf("    Capabilities:0x%08X\r\n", l_psmb_reponse->Capabilities);
        printf("    SystemTime:0x%08X%08X\r\n", l_psmb_reponse->SystemTime.dwHighDateTime, l_psmb_reponse->SystemTime.dwLowDateTime);
        printf("    ServerTimeZone:0x%04X\r\n", l_psmb_reponse->ServerTimeZone);
        printf("    ChallengeLength:0x%02X\r\n", l_psmb_reponse->ChallengeLength);

        printf("\r\n");

        printf("Data->\r\n");

        PSMB_Data_NTLANManager_response l_psmbdata_reponse = (PSMB_Data_NTLANManager_response)a_psmb_data;
        printf("    ByteCount:%d\r\n", l_psmbdata_reponse->ByteCount);
        if (l_psmbdata_reponse->ByteCount > 0)
        {
            ULONG l_ulong_index = 0;
            UCHAR* l_ucharptr_data = (UCHAR*)l_psmbdata_reponse->Challenge;
            printf("    Challenge: ");
            for (size_t i = 0; i < l_psmb_reponse->ChallengeLength; i++)
            {
                printf("0x%02X ", l_psmbdata_reponse->Challenge[i]);
            }
            printf("\r\n");

            //DANGEROUS!!
            printf("    DomainName:");
            WCHAR* l_wcharptr_currentPointer = (WCHAR*)(l_psmbdata_reponse->Challenge + l_psmb_reponse->ChallengeLength);
            WCHAR* l_wcharptr_oldPointer = l_wcharptr_currentPointer;

            for (size_t i = 0; i < (l_psmbdata_reponse->ByteCount - l_psmb_reponse->ChallengeLength); i++)
            {
                if (l_wcharptr_currentPointer[i] == 0)
                {
                    printf("%ws ", l_wcharptr_oldPointer);
                    l_wcharptr_oldPointer = l_wcharptr_currentPointer + i + 1;
                }
            }
        }
        printf("\r\n");
    }
}

void NegotiateReader::DumpRequest(PSMB_Parameters a_psmb_parameters, PSMB_Data a_psmb_data) {
    printf("Parameter->\r\n");

    printf("    WordCount:%d\r\n", a_psmb_parameters->WordCount);
    printf("    Words:");
    for (size_t i = 0; i < a_psmb_parameters->WordCount; i++)
    {
        printf("0x%04x  ", a_psmb_parameters->Words[i]);
    }
    printf("\r\n");

    printf("Data->\r\n");

    printf("    ByteCount:%d\r\n", a_psmb_data->ByteCount);
    if (a_psmb_data->ByteCount >= 0x2)
    {
        PSMB_Dialect l_psmb_dialect = (PSMB_Dialect)a_psmb_data->Bytes;
        printf("    dialectstr->\r\n");
        printf("        BufferFormat:0x%02x\r\n", l_psmb_dialect->BufferFormat);

        std::string l_string_instance((const char*)l_psmb_dialect->DialectString, a_psmb_data->ByteCount - sizeof(USHORT) - sizeof(UCHAR));
        printf("        DialectString:%s\r\n", l_string_instance.c_str());
    }
    printf("\r\n");
}