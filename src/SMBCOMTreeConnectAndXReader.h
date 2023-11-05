#pragma once
#include "BaseClass.h"

#pragma pack(push)
#pragma pack(1)
typedef struct _SMB_Parameters_SMBCOMTreeConnectAndXRequest
{
    UCHAR  WordCount;
    UCHAR  AndXCommand;
    UCHAR  AndXReserved;
    USHORT AndXOffset;
    USHORT Flags;
    USHORT PasswordLength;
}SMB_Parameters_SMBCOMTreeConnectAndXRequest, * PSMB_Parameters_SMBCOMTreeConnectAndXRequest;

typedef struct _SMB_Data_SMBCOMTreeConnectAndXRequest
{
    USHORT ByteCount;
    /*UCHAR      Password[PasswordLength];
    UCHAR      Pad[];
    SMB_STRING Path;
    OEM_STRING Service;*/
}SMB_Data_SMBCOMTreeConnectAndXRequest, * PSMB_Data_SMBCOMTreeConnectAndXRequest;

typedef struct _SMB_Parameters_SMBCOMTreeConnectAndXResponse
{
    UCHAR  WordCount;
    UCHAR  AndXCommand;
    UCHAR  AndXReserved;
    USHORT AndXOffset;
    USHORT OptionalSupport;
}SMB_Parameters_SMBCOMTreeConnectAndXResponse, * PSMB_Parameters_SMBCOMTreeConnectAndXResponse;

typedef struct _SMB_Data_SMBCOMTreeConnectAndXResponse
{
    USHORT ByteCount;
    //OEM_STRING Service;
    //SMB_STRING NativeFileSystem;
}SMB_Data_SMBCOMTreeConnectAndXResponse, * PSMB_Data_SMBCOMTreeConnectAndXResponse;

class SMBCOMTreeConnectAndXReader : public SMBReadBaseClass {
public:
    SMBCOMTreeConnectAndXReader();
    virtual ~SMBCOMTreeConnectAndXReader();
    static SMBCOMTreeConnectAndXReader* GetInstance();
    virtual void DumpResponse(PSMB_HEADER a_psmb_header, PSMB_Parameters a_psmb_parameters, PSMB_Data a_psmb_data) override;
    virtual void DumpRequest(PSMB_HEADER a_psmb_header, PSMB_Parameters a_psmb_parameters, PSMB_Data a_psmb_data) override;
};
#pragma pack(pop)
