#include "functions.h"

std::ofstream file;

#pragma region device

/* initializes vmm
*/
bool c_device::connect()
{
	file = std::ofstream("error_log.txt", std::ofstream::out | std::ofstream::trunc);

	std::vector<LPSTR> args{};
	for (auto arg : o_args)
		args.push_back((LPSTR)(const char*)arg);

	handle = VMMDLL_Initialize(args.size(), args.data());
	if (handle)
	{
		VMMDLL_ConfigGet(handle, LC_OPT_FPGA_FPGA_ID, &id);
		VMMDLL_ConfigGet(handle, LC_OPT_FPGA_VERSION_MAJOR, &major_version);
		VMMDLL_ConfigGet(handle, LC_OPT_FPGA_VERSION_MINOR, &minor_version);

		connected = true;
	}
	else
		file << "failed to connect to device\n";

	return handle;
}

/* closes vmm handle
*/
void c_device::disconnect()
{
	VMMDLL_Close(handle);
	
	connected = false;

	file.close();
}

int c_device::error(const char* error)
{
	printf(error);

	file << error;

	disconnect();

	system("pause");

	return 0;
}

/* return type -> std::vector<PVMMDLL_MAP_SERVICEENTRY>
*  gets all services running on target machine
*/
std::vector<PVMMDLL_MAP_SERVICEENTRY> c_device::get_service_list()
{
	std::vector<PVMMDLL_MAP_SERVICEENTRY> service_data_list{};

	PVMMDLL_MAP_SERVICE pServiceMap = NULL;

	bool result = VMMDLL_Map_GetServicesU(handle, &pServiceMap);
	if (!result)
	{
		printf("[-] failed GetServicesU call\n");
		return {};
	}

	if (pServiceMap->dwVersion != VMMDLL_MAP_SERVICE_VERSION)
	{
		printf("[-] bad version\n");
		return {};
	}

	for (int i = 0; i < pServiceMap->cMap; i++)
		service_data_list.push_back(pServiceMap->pMap + i);

	return service_data_list;
}

/* return type -> std::vector<user_map_data_t>
*  gets all users found on the target machine
*/
std::vector<user_map_data_t> c_device::get_users()
{
	std::vector<user_map_data_t> user_map_list{};

	PVMMDLL_MAP_USER pUserMap = NULL;
	DWORD PcbUserMap = 0;

	bool result = VMMDLL_Map_GetUsersU(handle, &pUserMap);
	if (!result)
	{
		printf("[-] failed GetUsersU call\n");
		return {};
	}

	if (pUserMap->dwVersion != VMMDLL_MAP_USER_VERSION)
	{
		printf("[-] bad version\n");
		return {};
	}

	for (int i = 0; i < pUserMap->cMap; i++)
	{
		PVMMDLL_MAP_USERENTRY entry = &pUserMap->pMap[i];

		user_map_data_t data{};
		memcpy(data.future_use1, entry->_FutureUse1, sizeof(entry->_FutureUse1));
		memcpy(data.future_use2, entry->_FutureUse2, sizeof(entry->_FutureUse2));

		data.usz_sid = entry->uszSID;
		data.usz_text = entry->uszText;
		data.va_reg_hive = entry->vaRegHive;
		data.wsz_sid = entry->wszSID;
		data.wsz_text = entry->wszText;

		user_map_list.push_back(data);
	}

	return user_map_list;
}

/* return type -> std::vector<DWORD>
*  gets all process id's currently active on the target machine
*/
std::vector<DWORD> c_device::get_pid_list()
{
	std::vector<DWORD> pids{};

	DWORD* pPIDs = NULL;
	ULONG64 pcPIDs = 0;

	bool result = VMMDLL_PidList(handle, NULL, &pcPIDs);
	if (!result)
	{
		printf("[-] failed PidList call");

		return {};
	}

	pPIDs = (DWORD*)LocalAlloc(LMEM_ZEROINIT, pcPIDs * sizeof(DWORD));

	result = VMMDLL_PidList(handle, pPIDs, &pcPIDs);
	if (!result)
	{
		printf("[-] failed PidList call");

		return {};
	}

	if (!pPIDs)
	{
		printf("[-] list is nullptr\n");

		return {};
	}

	for (int i = 0; i < pcPIDs; i++)
		pids.push_back(pPIDs[i]);

	LocalFree(pPIDs);

	return pids;
}

std::vector<c_process> c_device::get_process_list()
{
	std::vector<c_process> process_list{};
	
	auto pids = get_pid_list();
	if (pids.empty())
		return {};

	for (auto pid : pids)
		process_list.push_back(process_from_pid(pid));

	return process_list;
}

c_process c_device::process_from_name(const char* str)
{
	return c_process(str);
}

c_process c_device::process_from_pid(DWORD pid)
{
	return c_process(pid);
}

/* return type -> machine_data_t
*  gets generic machine data from registry keys
*/
machine_data_t c_device::get_machine_data()
{
	int current_build = c_registry("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\CurrentBuild", REG_SZ).get_int();
	const char* edition = c_registry("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\CompositionEditionID", REG_SZ).get();
	const char* display_version = c_registry("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\DisplayVersion", REG_SZ).get();
	const char* processor_name = c_registry("HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0\\ProcessorNameString", REG_SZ).get();
	const char* motherboard_manufacturer_name = c_registry("HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS\\BaseBoardManufacturer", REG_SZ).get();
	const char* motherboard_name = c_registry("HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS\\BaseBoardProduct", REG_SZ).get();

	return { current_build, edition, display_version, processor_name, motherboard_manufacturer_name, motherboard_name };
}

#pragma endregion device

#pragma region process

/* return type -> c_process
*  creates a process instance from it's name
*/
c_process::c_process(const char* process_name)
{
	if (strcmp(process_name, "") == 0)
		return;

	failed = false;

	if (!VMMDLL_PidGetFromName(handle, CC_TO_LPSTR(process_name), &process_id))
		failed = true;
	else
	{
		SIZE_T cbProcessInformation = sizeof(VMMDLL_PROCESS_INFORMATION);
		ZeroMemory(&information, sizeof(VMMDLL_PROCESS_INFORMATION));
		information.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
		information.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;

		bool result = VMMDLL_ProcessGetInformation(handle, process_id, &information, &cbProcessInformation);
		if (!result)
			printf("[-] Failed GetProcessInformation call\n");
	}
}

/* return type -> c_process
*  creates a process instance from it's process id
*/
c_process::c_process(DWORD pid_in)
{
	process_id = pid_in;

	SIZE_T cbProcessInformation = sizeof(VMMDLL_PROCESS_INFORMATION);
	ZeroMemory(&information, sizeof(VMMDLL_PROCESS_INFORMATION));
	information.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
	information.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;

	bool result = VMMDLL_ProcessGetInformation(handle, process_id, &information, &cbProcessInformation);
	if (!result)
		printf("[-] Failed GetProcessInformation call\n");
}

/* return type -> module_data_t
*  finds a module from it's name
*/
module_data_t c_process::module_from_name(const char* module_name)
{
	PVMMDLL_MAP_MODULEENTRY module_entry;
	bool result = VMMDLL_Map_GetModuleFromNameU(handle, this->get_pid(), CC_TO_LPSTR(module_name), &module_entry);

	if (!module_entry)
		return { 0, 0, true };

	return { module_entry->vaBase, module_entry->cbImageSize, !result };
}

/* return type -> std::vector<module_map_data_t>
*  get all modules inside of a process instance
*/
std::vector<module_map_data_t> c_process::get_module_list()
{
	std::vector<module_map_data_t> map_data_list{};

	DWORD cbPteMap = 0;
	PVMMDLL_MAP_PTE pPteMap = NULL;

	bool result = VMMDLL_Map_GetPteU(handle, this->get_pid(), TRUE, &pPteMap);
	if (!result)
	{
		printf("[-] failed GetPte call\n");
		return {};
	}

	if (pPteMap->dwVersion != VMMDLL_MAP_PTE_VERSION)
	{
		printf("[-] bad version\n");
		return {};
	}

	for (int i = 0; i < pPteMap->cMap; i++)
	{
		PVMMDLL_MAP_PTEENTRY entry = &pPteMap->pMap[i];
		module_map_data_t map_data = { entry->vaBase, entry->cPages, entry->fPage, entry->fWoW64, entry->_FutureUse1, (const char*)entry->uszText, entry->_Reserved1, entry->cSoftware };

		map_data_list.push_back(map_data);
	}

	pPteMap = NULL;

	return map_data_list;
}

/* return type -> std::vector<PVMMDLL_MAP_HANDLEENTRY>
*  get all handles inside of a process instance
*/
std::vector<PVMMDLL_MAP_HANDLEENTRY> c_process::get_handle_list()
{
	std::vector<PVMMDLL_MAP_HANDLEENTRY> handle_list_data{};

	PVMMDLL_MAP_HANDLE pHandleMap = NULL;

	bool result = VMMDLL_Map_GetHandleU(handle, this->get_pid(), &pHandleMap);
	if (!result)
	{
		printf("[-] failed GetHandleU call\n");
		return {};
	}

	if (pHandleMap->dwVersion != VMMDLL_MAP_HANDLE_VERSION)
	{
		printf("[-] bad version\n");
		return {};
	}

	for (int i = 0; i < pHandleMap->cMap; i++)
		handle_list_data.push_back(&pHandleMap->pMap[i]);

	LocalFree(pHandleMap);
	pHandleMap = NULL;

	return handle_list_data;
}

#pragma endregion process

std::string to_hex(std::string v)
{
	std::ostringstream oss;

	for (std::string::size_type i = 0; i < v.size(); ++i)
		oss << std::hex << (int)v[i] << " ";

	return oss.str();
}

/* return type -> std::vector<VMMDLL_MAP_VADENTRY>
*  gets all vads inside of a process instance
*/
std::vector<VMMDLL_MAP_VADENTRY> c_process::get_map_list()
{
	std::vector<VMMDLL_MAP_VADENTRY> maps{};

	PVMMDLL_MAP_VAD pVadMap = NULL;

	bool result = VMMDLL_Map_GetVadU(handle, process_id, TRUE, &pVadMap);
	if (!result)
	{
		printf("[-] failed GetVadU call\n");

		return {};
	}

	if (pVadMap->dwVersion != VMMDLL_MAP_VAD_VERSION)
	{
		printf("[-] bad version\n");

		VMMDLL_MemFree(pVadMap);

		pVadMap = NULL;

		return {};
	}

	for (int i = 0; i < pVadMap->cMap; i++)
		maps.push_back(pVadMap->pMap[i]);

	VMMDLL_MemFree(pVadMap);

	pVadMap = NULL;

	return maps;
}

#pragma region memory

c_memory c_process::get_memory()
{
	return c_memory(this->get_pid());
}

/* return type -> std::vector<section_data_t>
*  gets all sections inside of a module
*/
std::vector<section_data_t> c_memory::get_sections(LPSTR module_name)
{
	std::vector<section_data_t> sections_list{};

	LPWSTR module_name_w = LPSTR_TO_LPWSTR(module_name);

	uint64_t base = VMMDLL_ProcessGetModuleBaseW(handle, this->get_pid(), module_name_w);

	DWORD sections;
	PIMAGE_SECTION_HEADER section_headers;
	BOOL result = VMMDLL_ProcessGetSectionsU(handle, this->get_pid(), module_name, NULL, 0, &sections);
	if (!result)
		return {};

	section_headers = (PIMAGE_SECTION_HEADER)LocalAlloc(LMEM_ZEROINIT, sections * sizeof(IMAGE_SECTION_HEADER));
	if (!section_headers)
		return {};

	result = VMMDLL_ProcessGetSectionsU(handle, this->get_pid(), (LPSTR)module_name, section_headers, sections, &sections);
	if (result)
		for (int i = 0; i < sections; i++)
			sections_list.push_back({ base + section_headers[i].VirtualAddress, base + section_headers[i].VirtualAddress + section_headers[i].Misc.VirtualSize, (const char*)section_headers[i].Name, section_headers[i].Characteristics });

	return sections_list;
}

/* return type -> bool
*  checks if an address is inside a specific section of a module
*/
bool c_memory::is_in_section(uint64_t address, section_data_t section_data)
{
	return address > section_data.start && address < section_data.end;
}

static const char* hexdigits =
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
"\000\001\002\003\004\005\006\007\010\011\000\000\000\000\000\000"
"\000\012\013\014\015\016\017\000\000\000\000\000\000\000\000\000"
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
"\000\012\013\014\015\016\017\000\000\000\000\000\000\000\000\000"
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000";

static uint8_t get_byte(const char* hex)
{
	return (uint8_t)((hexdigits[hex[0]] << 4) | (hexdigits[hex[1]]));
}

/* return type -> uint64_t
*  scans memory for a signature of bytes from range_start to range_end
*  
*  signature bytes are in hex format and for wildcards are specified by "?"
*/
uint64_t c_memory::find_signature(const char* signature, uint64_t range_start, uint64_t range_end)
{
	const char* pat = signature;
	uint64_t first_match = 0;
	uint8_t* buffer = nullptr;

	buffer = new uint8_t[range_end - range_start];
	if (buffer)
		VMMDLL_MemReadEx(handle, this->get_pid(), range_start, buffer, range_end - range_start, 0, VMMDLL_FLAG_NOCACHE);

	auto readbuf = [=](uint64_t addr) -> uint8_t
	{
		return buffer[addr - range_start];
	};

	for (uint64_t current = range_start; current < range_end; current++)
	{
		if (!*pat)
			goto found;

		if (*pat == '\?' || readbuf(current) == get_byte(pat))
		{
			if (!first_match)
				first_match = current;

			if (!pat[2])
				goto found;

			if (*pat != '\?')
				pat += 3;
			else
				pat += 2;
		}
		else
		{
			pat = signature;
			first_match = 0;
		}
	}

	first_match = 0;
found:
	if (buffer)
		delete[] buffer;

	return first_match;
}

/* return type -> uint64_t
*  scans memory for a string by converting the string to hex format for the find_signature function
*/
uint64_t c_memory::string_scan(const char* str, uint64_t start, uint64_t end)
{
	uint64_t result = find_signature(to_hex(str).c_str(), start, end);

	return result;
}

/* return type -> none
*  initializes a scatter handle to be used by other functions
*/
void c_memory::initialize_scatter()
{
	scatter_handle = VMMDLL_Scatter_Initialize(handle, this->get_pid(), VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_NOPAGING_IO);
	scatters = 0;
}

/* return type -> none
*  uninitializes the current scatter handle
*/
void c_memory::uninitialize_scatter()
{
	VMMDLL_Scatter_CloseHandle(scatter_handle);
}

#pragma endregion memory