#pragma once
#include "windows.h"
#include "SMBCommandType.h"

class SMBReadBaseClass {
public:
	SMBReadBaseClass() = default;
	virtual ~SMBReadBaseClass() = default;
	virtual void DumpResponse(PSMB_HEADER a_psmb_header, PSMB_Parameters a_psmb_parameters, PSMB_Data a_psmb_data) = 0;
	virtual void DumpRequest(PSMB_HEADER a_psmb_header, PSMB_Parameters a_psmb_parameters, PSMB_Data a_psmb_data) = 0;
};