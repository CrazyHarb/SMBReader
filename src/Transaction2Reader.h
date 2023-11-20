#pragma once
#include "BaseClass.h"

#pragma pack(push)
#pragma pack(1)
typedef struct _SMB_Parameters_SMBCOMTranscation2Response
{
    UCHAR  WordCount;
    USHORT TotalParameterCount;
    USHORT TotalDataCount;
    UCHAR  Reserved1;
    USHORT ParameterCount;
    USHORT ParameterOffset;
    USHORT ParameterDisplacement;
    USHORT DataCount;
    USHORT DataOffset;
    USHORT DataDisplacement;
    UCHAR  SetupCount;
    UCHAR  Reserved2;
    USHORT Setup[0];
}SMB_Parameters_SMBCOMTranscation2Response, * PSMB_Parameters_SMBCOMTranscation2Response;

typedef struct _SMB_Data_SMBCOMTranscation2Response
{
    USHORT ByteCount;
    /*UCHAR Name;
     UCHAR Pad1[];
     UCHAR Trans2_Parameters[ParameterCount];
     UCHAR Pad2[];
     UCHAR Trans2_Data[DataCount];*/
}SMB_Data_SMBCOMTranscation2Response, * PSMB_Data_SMBCOMTranscation2Response;

typedef struct _SMB_Parameters_SMBCOMTranscation2Request
{
    UCHAR  WordCount;
    USHORT TotalParameterCount;
    USHORT TotalDataCount;
    USHORT MaxParameterCount;
    USHORT MaxDataCount;
    UCHAR  MaxSetupCount;
    UCHAR  Reserved1;
    USHORT Flags;
    ULONG  Timeout;
    USHORT Reserved2;
    USHORT ParameterCount;
    USHORT ParameterOffset;
    USHORT DataCount;
    USHORT DataOffset;
    UCHAR  SetupCount;
    UCHAR  Reserved3;
    USHORT Setup[0];
}SMB_Parameters_SMBCOMTranscation2Request, * PSMB_Parameters_SMBCOMTranscation2Request;

typedef struct _SMB_Data_SMBCOMTranscation2Request
{
    USHORT ByteCount;
    /*UCHAR Name;
     UCHAR Pad1[];
     UCHAR Trans2_Parameters[ParameterCount];
     UCHAR Pad2[];
     UCHAR Trans2_Data[DataCount];*/
}SMB_Data_SMBCOMTranscation2Request, * PSMB_Data_SMBCOMTranscation2Request;

class SMBCOMTranscation2Reader : public SMBReadBaseClass {
public:
    SMBCOMTranscation2Reader();
    virtual ~SMBCOMTranscation2Reader();
    static SMBCOMTranscation2Reader* GetInstance();
    virtual void DumpResponse(PSMB_HEADER a_psmb_header, PSMB_Parameters a_psmb_parameters, PSMB_Data a_psmb_data) override;
    virtual void DumpRequest(PSMB_HEADER a_psmb_header, PSMB_Parameters a_psmb_parameters, PSMB_Data a_psmb_data) override;
};
#pragma pack(pop)
