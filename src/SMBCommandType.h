#ifndef __SMB_COMMAND_TYPE__
#define __SMB_COMMAND_TYPE__
#include "windows.h"
#include <string>

//commands
#define SMB_COM_CREATE_DIRECTORY 	0x00	//Create a new directory.
#define SMB_COM_DELETE_DIRECTORY 	0x01	//Delete an empty directory.
#define SMB_COM_OPEN 	0x02	//Open a file.
#define SMB_COM_CREATE 	0x03	//Create or open a file.
#define SMB_COM_CLOSE 	0x04	//Close a file.
#define SMB_COM_FLUSH 	0x05	//Flush data for a file, or all files associated with a client, PID pair.
#define SMB_COM_DELETE 	0x06	//Delete a file.
#define SMB_COM_RENAME 	0x07	//Rename a file or set of files.
#define SMB_COM_QUERY_INFORMATION 	0x08	//Get file attributes.
#define SMB_COM_SET_INFORMATION 	0x09	//Set file attributes.
#define SMB_COM_READ 	0x0A	//Read from a file.
#define SMB_COM_WRITE 	0x0B	//Write to a file.
#define SMB_COM_LOCK_BYTE_RANGE 	0x0C	//Request a byte-range lock on a file.
#define SMB_COM_UNLOCK_BYTE_RANGE 	0x0D	//Release a byte-range lock on a file.
#define SMB_COM_CREATE_TEMPORARY 	0x0E	//Create a temporary file.
#define SMB_COM_CREATE_NEW 	0x0F	//Create and open a new file.
#define SMB_COM_CHECK_DIRECTORY 	0x10	//Verify that the specified pathname resolves to a directory.
#define SMB_COM_PROCESS_EXIT 	0x11	//Indicate process exit.
#define SMB_COM_SEEK 	0x12	//Set the current file pointer within a file.
#define SMB_COM_LOCK_AND_READ 	0x13	//Lock and read a byte-range within a file.
#define SMB_COM_WRITE_AND_UNLOCK 	0x14	//Write and unlock a byte-range within a file.
//#define Unused	//0x15 0x19	
#define SMB_COM_READ_RAW 	0x1A	//Read a block in raw mode.
#define SMB_COM_READ_MPX 	0x1B	//Multiplexed block read.
#define SMB_COM_READ_MPX_SECONDARY 	0x1C	//Multiplexed block read, secondary request.
#define SMB_COM_WRITE_RAW 	0x1D	//Write a block in raw mode.
#define SMB_COM_WRITE_MPX 	0x1E	//Multiplexed block write.
#define SMB_COM_WRITE_MPX_SECONDARY 	0x1F	//Multiplexed block write, secondary request.
#define SMB_COM_WRITE_COMPLETE 	0x20	//Raw block write, final response.
#define SMB_COM_QUERY_SERVER 	0x21	//Reserved, but not implemented.
#define SMB_COM_SET_INFORMATION2 	0x22	//Set an extended set of file attributes.
#define SMB_COM_QUERY_INFORMATION2 	0x23	//Get an extended set of file attributes.
#define SMB_COM_LOCKING_ANDX 	0x24	//Lock multiple byte ranges; AndX chaining.
#define SMB_COM_TRANSACTION 	0x25	//Transaction.
#define SMB_COM_TRANSACTION_SECONDARY 	0x26	//Transaction secondary request.
#define SMB_COM_IOCTL 	0x27	//Pass an I/O Control function request to the server.
#define SMB_COM_IOCTL_SECONDARY 	0x28	//IOCTL secondary request.
#define SMB_COM_COPY 	0x29	//Copy a file or directory.
#define SMB_COM_MOVE 	0x2A	//Move a file or directory.
#define SMB_COM_ECHO 	0x2B	//Echo request (ping).
#define SMB_COM_WRITE_AND_CLOSE 	0x2C	//Write to and close a file.
#define SMB_COM_OPEN_ANDX 	0x2D	//Extended file open with AndX chaining.
#define SMB_COM_READ_ANDX 	0x2E	//Extended file read with AndX chaining.
#define SMB_COM_WRITE_ANDX 	0x2F	//Extended file write with AndX chaining.
#define SMB_COM_NEW_FILE_SIZE 	0x30	//Reserved, but not implemented.
#define SMB_COM_CLOSE_AND_TREE_DISC 	0x31	//Close an open file and tree disconnect.
#define SMB_COM_TRANSACTION2 	0x32	//Transaction 2 format request/response.
#define SMB_COM_TRANSACTION2_SECONDARY 	0x33	//Transaction 2 secondary request.
#define SMB_COM_FIND_CLOSE2 	0x34	//Close an active search.
#define SMB_COM_FIND_NOTIFY_CLOSE 	0x35	//Notification of the closure of an active search.
//#define Unused	//0x36	-0x5F	
//#define Reserved	//0x60-0x6F	This range of codes was reserved for use by the "xenix1.1" dialect of SMB. See [MSFT-XEXTNP]. [XOPEN-SMB] page 41 lists this range as "Reserved for proprietary dialects."	
#define SMB_COM_TREE_CONNECT 	0x70	//Tree connect.
#define SMB_COM_TREE_DISCONNECT 	0x71	//Tree disconnect.
#define SMB_COM_NEGOTIATE 	0x72	//Negotiate protocol dialect.
#define SMB_COM_SESSION_SETUP_ANDX 	0x73	//Session Setup with AndX chaining.
#define SMB_COM_LOGOFF_ANDX 	0x74	//User logoff with AndX chaining.
#define SMB_COM_TREE_CONNECT_ANDX 	0x75	//Tree connect with AndX chaining.
//#define Unused	//0x76-0x7D	
#define SMB_COM_SECURITY_PACKAGE_ANDX 	0x7E	//Negotiate security packages with AndX chaining.
//#define Unused	0x7F	
#define SMB_COM_QUERY_INFORMATION_DISK 	0x80	//Retrieve file system information from the server.
#define SMB_COM_SEARCH 	0x81	//Directory wildcard search.
#define SMB_COM_FIND 	0x82	//Start or continue an extended wildcard directory search.
#define SMB_COM_FIND_UNIQUE 	0x83	//Perform a one-time extended wildcard directory search.
#define SMB_COM_FIND_CLOSE 	0x84	//End an extended wildcard directory search.
//#define Unused	//0x85-0x9F	
#define SMB_COM_NT_TRANSACT 	0xA0	//NT format transaction request/response.
#define SMB_COM_NT_TRANSACT_SECONDARY 	0xA1	//NT format transaction secondary request.
#define SMB_COM_NT_CREATE_ANDX 	0xA2	//Create or open a file or a directory.
//#define Unused	0xA3	
#define SMB_COM_NT_CANCEL 	0xA4	//Cancel a request currently pending at the server.
#define SMB_COM_NT_RENAME 	0xA5	//File rename with extended semantics.
//#define Unused	//0xA6-0xBF	
#define SMB_COM_OPEN_PRINT_FILE 	0xC0	//Create a print queue spool file.
#define SMB_COM_WRITE_PRINT_FILE 	0xC1	//Write to a print queue spool file.
#define SMB_COM_CLOSE_PRINT_FILE 	0xC2	//Close a print queue spool file.
#define SMB_COM_GET_PRINT_QUEUE 	0xC3	//Request print queue information.
//#define Unused	//0xC4-0xCF	
//#define Reserved	//0xD0-0xD7	Messenger Service command codes.
#define SMB_COM_READ_BULK 	0xD8	//Reserved, but not implemented.
#define SMB_COM_WRITE_BULK 	0xD9	//Reserved, but not implemented.
#define SMB_COM_WRITE_BULK_DATA 	0xDA	//Reserved, but not implemented.
//#define Unused	//0xDB-0xFD	
#define SMB_COM_INVALID 	0xFE	//As the name suggests, this command code is a designated invalid command and SHOULD NOT be used.
#define SMB_COM_NO_ANDX_COMMAND 	0xFF	//Also known as the "NIL" command. It identifies the end of an AndX Chain, and is only valid in that context. See section 2.2.3.4.


//flags:
#define SMB_FLAGS_LOCK_AND_READ_OK 0x01
#define SMB_FLAGS_BUF_AVAIL 0x02
#define SMB_FLAGS_CASE_INSENSITIVE 0x08
#define SMB_FLAGS_CANONICALIZED_PATHS 0x10
#define SMB_FLAGS_OPLOCK 0x20
#define SMB_FLAGS_OPBATCH 0x40
#define SMB_FLAGS_REPLY 0x80

#pragma pack(push)
#pragma pack(1)
typedef struct _SMB_COMMAND_STRING {
	UCHAR m_uchar_command;
	std::string m_string_description;
}SMB_COMMAND_STRING, * PSMB_COMMAND_STRING;

const SMB_COMMAND_STRING g_array_smbCommand[] = {
{SMB_COM_CREATE_DIRECTORY 	, "Create a new directory."},
{SMB_COM_DELETE_DIRECTORY 	, "Delete an empty directory."},
{SMB_COM_OPEN 	, "Open a file."},
{SMB_COM_CREATE 	, "Create or open a file."},
{SMB_COM_CLOSE 	, "Close a file."},
{SMB_COM_FLUSH 	, "Flush data for a file, or all files associated with a client, PID pair."},
{SMB_COM_DELETE 	, "Delete a file."},
{SMB_COM_RENAME 	, "Rename a file or set of files."},
{SMB_COM_QUERY_INFORMATION 	, "Get file attributes."},
{SMB_COM_SET_INFORMATION 	, "Set file attributes."},
{SMB_COM_READ 	, "Read from a file."},
{SMB_COM_WRITE 	, "Write to a file."},
{SMB_COM_LOCK_BYTE_RANGE 	, "Request a byte-range lock on a file."},
{SMB_COM_UNLOCK_BYTE_RANGE 	, "Release a byte-range lock on a file."},
{SMB_COM_CREATE_TEMPORARY 	, "Create a temporary file."},
{SMB_COM_CREATE_NEW , "Create and open a new file."},
{SMB_COM_CHECK_DIRECTORY 	, "Verify that the specified pathname resolves to a directory."},
{SMB_COM_PROCESS_EXIT 	, "Indicate process exit."},
{SMB_COM_SEEK 	, "Set the current file pointer within a file."},
{SMB_COM_LOCK_AND_READ 	, "Lock and read a byte-range within a file."},
{SMB_COM_WRITE_AND_UNLOCK 	, "Write and unlock a byte-range within a file."},
{SMB_COM_READ_RAW 	, "Read a block in raw mode."},
{SMB_COM_READ_MPX 	, "Multiplexed block read."},
{SMB_COM_READ_MPX_SECONDARY 	, "Multiplexed block read, secondary request."},
{SMB_COM_WRITE_RAW 	, "Write a block in raw mode."},
{SMB_COM_WRITE_MPX 	, "Multiplexed block write."},
{SMB_COM_WRITE_MPX_SECONDARY 	, "Multiplexed block write, secondary request."},
{SMB_COM_WRITE_COMPLETE 	, "Raw block write, final response."},
{SMB_COM_QUERY_SERVER 	, "Reserved, but not implemented."},
{SMB_COM_SET_INFORMATION2 	, "Set an extended set of file attributes."},
{SMB_COM_QUERY_INFORMATION2 	, "Get an extended set of file attributes."},
{SMB_COM_LOCKING_ANDX 	, "Lock multiple byte ranges; AndX chaining."},
{SMB_COM_TRANSACTION 	, "Transaction."},
{SMB_COM_TRANSACTION_SECONDARY 	, "Transaction secondary request."},
{SMB_COM_IOCTL 	, "Pass an I/O Control function request to the server."},
{SMB_COM_IOCTL_SECONDARY 	, "IOCTL secondary request."},
{SMB_COM_COPY 	, "Copy a file or directory."},
{SMB_COM_MOVE 	, "Move a file or directory."},
{SMB_COM_ECHO 	, "Echo request (ping)."},
{SMB_COM_WRITE_AND_CLOSE 	, "Write to and close a file."},
{SMB_COM_OPEN_ANDX 	, "Extended file open with AndX chaining."},
{SMB_COM_READ_ANDX 	, "Extended file read with AndX chaining."},
{SMB_COM_WRITE_ANDX 	, "Extended file write with AndX chaining."},
{SMB_COM_NEW_FILE_SIZE 	, "Reserved, but not implemented."},
{SMB_COM_CLOSE_AND_TREE_DISC 	, "Close an open file and tree disconnect."},
{SMB_COM_TRANSACTION2 	, "Transaction 2 format request/response."},
{SMB_COM_TRANSACTION2_SECONDARY 	, "Transaction 2 secondary request."},
{SMB_COM_FIND_CLOSE2 	, "Close an active search."},
{SMB_COM_FIND_NOTIFY_CLOSE 	, "Notification of the closure of an active search."},
{SMB_COM_TREE_CONNECT 	, "Tree connect."},
{SMB_COM_TREE_DISCONNECT 	, "Tree disconnect."},
{SMB_COM_NEGOTIATE 	, "Negotiate protocol dialect."},
{SMB_COM_SESSION_SETUP_ANDX 	, "Session Setup with AndX chaining."},
{SMB_COM_LOGOFF_ANDX 	, "User logoff with AndX chaining."},
{SMB_COM_TREE_CONNECT_ANDX 	, "Tree connect with AndX chaining."},
{SMB_COM_SECURITY_PACKAGE_ANDX 	, "Negotiate security packages with AndX chaining."},
{SMB_COM_QUERY_INFORMATION_DISK 	, "Retrieve file system information from the server."},
{SMB_COM_SEARCH 	, "Directory wildcard search."},
{SMB_COM_FIND 	, "Start or continue an extended wildcard directory search."},
{SMB_COM_FIND_UNIQUE 	, "Perform a one-time extended wildcard directory search."},
{SMB_COM_FIND_CLOSE 	, "End an extended wildcard directory search."},
{SMB_COM_NT_TRANSACT 	, "NT format transaction request/response."},
{SMB_COM_NT_TRANSACT_SECONDARY 	, "NT format transaction secondary request."},
{SMB_COM_NT_CREATE_ANDX 	, "Create or open a file or a directory."},
{SMB_COM_NT_CANCEL 	, "Cancel a request currently pending at the server."},
{SMB_COM_NT_RENAME 	, "File rename with extended semantics."},
{SMB_COM_OPEN_PRINT_FILE 	, "Create a print queue spool file."},
{SMB_COM_WRITE_PRINT_FILE 	, "Write to a print queue spool file."},
{SMB_COM_CLOSE_PRINT_FILE 	, "Close a print queue spool file."},
{SMB_COM_GET_PRINT_QUEUE 	, "Request print queue information."},
{SMB_COM_READ_BULK 	, "Reserved, but not implemented."},
{SMB_COM_WRITE_BULK 	, "Reserved, but not implemented."},
{SMB_COM_WRITE_BULK_DATA 	, "Reserved, but not implemented."},
{SMB_COM_INVALID 	, "As the name suggests, this command code is a designated invalid command and SHOULD NOT be used."},
{SMB_COM_NO_ANDX_COMMAND 	, "Also known as the \"NIL\" command. It identifies the end of an AndX Chain, and is only valid in that context. See section 2.2.3.4."}
};

#define SMB_FLAGS2_UNICODE 0x8000

typedef DWORD SMB_ERROR;
typedef struct _SMB_HEADER {
	UCHAR Protocol[4];  // 0xff S M B
	UCHAR Command;
	SMB_ERROR Status;
	UCHAR Flags;
	USHORT Flags2;
	USHORT PIDHigh;
	UCHAR SecurityFeatures[8];
	USHORT Reserved;
	USHORT TID;
	USHORT PIDLow;
	USHORT UID;
	USHORT MID;
} SMB_HEADER, * PSMB_HEADER;

typedef struct _Security_Features {
	ULONG Key;
	USHORT CID;
	USHORT SequenceNumber;
} Security_Features, * PSecurity_Features;

typedef struct _SMB_Parameters {
	UCHAR WordCount;
	USHORT Words[0];
} SMB_Parameters, * PSMB_Parameters;

typedef struct _SMB_Data {
	USHORT ByteCount;
	UCHAR Bytes[0];
} SMB_Data, * PSMB_Data;

typedef struct SMB_Dialect
{
	UCHAR      BufferFormat;
	UCHAR	   DialectString[0]; //OEM_STRING
}_SMB_Dialect, * PSMB_Dialect;

//negotiate response NT LAN Manager
typedef struct _SMB_Parameters_NTLANManager_response
{
	UCHAR  WordCount;
	USHORT   DialectIndex;
	UCHAR    SecurityMode;
	USHORT   MaxMpxCount;
	USHORT   MaxNumberVcs;
	ULONG    MaxBufferSize;
	ULONG    MaxRawSize;
	ULONG    SessionKey;
	ULONG    Capabilities;
	FILETIME SystemTime;
	SHORT    ServerTimeZone;
	UCHAR    ChallengeLength;
} SMB_Parameters_NTLANManager_response, * PSMB_Parameters_NTLANManager_response;

typedef struct _SMB_Data_NTLANManager_response
{
	USHORT ByteCount;
	UCHAR  Challenge[0];
	//SMB_STRING  DomainName[];
}SMB_Data_NTLANManager_response,*PSMB_Data_NTLANManager_response;

#pragma pack(pop)
#endif