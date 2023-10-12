#pragma once
#include "BaseClass.h"

#pragma pack(push)
#pragma pack(1)
typedef struct _SMB_Parameters_SessionSetupAndXRequest
{
    UCHAR  WordCount;
    UCHAR  AndXCommand;
    UCHAR  AndXReserved;
    USHORT AndXOffset;
    USHORT MaxBufferSize;
    USHORT MaxMpxCount;
    USHORT VcNumber;
    ULONG  SessionKey;
    USHORT OEMPasswordLen;
    USHORT UnicodePasswordLen;
    ULONG  Reserved;
    ULONG  Capabilities;
}SMB_Parameters_SessionSetupAndX, * PSMB_Parameters_SessionSetupAndX;

typedef struct _SMB_Data_SessionSetupAndXRequest
{
    USHORT ByteCount;
    //UCHAR      OEMPassword[];
    //UCHAR      UnicodePassword[];
    //UCHAR      Pad[];
    //SMB_STRING AccountName[];
    //SMB_STRING PrimaryDomain[];
    //SMB_STRING NativeOS[];
    //SMB_STRING NativeLanMan[];
}SMB_Data_SessionSetupAndXRequest, * PSMB_Data_SessionSetupAndXRequest;

typedef struct _SMB_Parameters_SessionSetupAndXResponse
{
    UCHAR  WordCount;
    UCHAR  AndXCommand;
    UCHAR  AndXReserved;
    USHORT AndXOffset;
    USHORT Action;
}SMB_Parameters_SessionSetupAndXResponse, * PSMB_Parameters_SessionSetupAndXResponse;

typedef struct _SMB_Data_SessionSetupAndXResponse
{
    UCHAR  WordCount;
    /*UCHAR      Pad[];
    SMB_STRING NativeOS[];
    SMB_STRING NativeLanMan[];
    SMB_STRING PrimaryDomain[];*/
}SMB_Data_SessionSetupAndXResponse, * PSMB_Data_SessionSetupAndXResponse;

class SessionSetupAndXReader : public SMBReadBaseClass {
public:
	SessionSetupAndXReader();
	virtual ~SessionSetupAndXReader();
	static SessionSetupAndXReader* GetInstance();
	virtual void DumpResponse(PSMB_HEADER a_psmb_header, PSMB_Parameters a_psmb_parameters, PSMB_Data a_psmb_data) override;
	virtual void DumpRequest(PSMB_HEADER a_psmb_header, PSMB_Parameters a_psmb_parameters, PSMB_Data a_psmb_data) override;
};
#pragma pack(pop)
