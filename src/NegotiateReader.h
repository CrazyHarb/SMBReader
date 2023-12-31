#pragma once
#include "BaseClass.h"

class NegotiateReader : public SMBReadBaseClass {
public:
	NegotiateReader();
	virtual ~NegotiateReader();
	static NegotiateReader* GetInstance();
	virtual void DumpResponse(PSMB_HEADER a_psmb_header, PSMB_Parameters a_psmb_parameters, PSMB_Data a_psmb_data) override;
	virtual void DumpRequest(PSMB_HEADER a_psmb_header, PSMB_Parameters a_psmb_parameters, PSMB_Data a_psmb_data) override;
};