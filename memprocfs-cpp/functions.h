#pragma once
#include <Windows.h>
#include <vector>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <stdlib.h>
#include <fstream>

#include <vmmdll.h>

inline VMM_HANDLE handle;

inline DWORD FAILED_TO_FIND = -12348756;

//this is yucky
inline LPSTR CC_TO_LPSTR(const char* in)
{
	LPSTR out = new char[strlen(in) + 1];
	strcpy_s(out, strlen(in) + 1, in);

	return out;
}

inline LPWSTR CC_TO_LPWSTR(const wchar_t* in)
{
	LPWSTR out = new wchar_t[wcslen(in) + 1];
	wcscpy_s(out, wcslen(in) + 1, in);

	return out;
}

inline LPWSTR LPSTR_TO_LPWSTR(LPSTR in)
{
	int size = MultiByteToWideChar(CP_ACP, 0, in, -1, NULL, 0);
	LPWSTR out = new wchar_t[size];
	MultiByteToWideChar(CP_ACP, 0, in, -1, out, size);

	return out;
}

inline const char* LPWSTR_TO_CC(LPWSTR in)
{
	char buffer[500];
	wcstombs(buffer, in, 500);

	return buffer;
}

inline void vad_map__protection(_In_ PVMMDLL_MAP_VADENTRY pVad, _Out_writes_(6) LPSTR sz)
{
	BYTE vh = (BYTE)pVad->Protection >> 3;
	BYTE vl = (BYTE)pVad->Protection & 7;
	sz[0] = pVad->fPrivateMemory ? 'p' : '-';                                    // PRIVATE MEMORY
	sz[1] = (vh & 2) ? ((vh & 1) ? 'm' : 'g') : ((vh & 1) ? 'n' : '-');         // -/NO_CACHE/GUARD/WRITECOMBINE
	sz[2] = ((vl == 1) || (vl == 3) || (vl == 4) || (vl == 6)) ? 'r' : '-';     // COPY ON WRITE
	sz[3] = (vl & 4) ? 'w' : '-';                                               // WRITE
	sz[4] = (vl & 2) ? 'x' : '-';                                               // EXECUTE
	sz[5] = ((vl == 5) || (vl == 7)) ? 'c' : '-';                               // COPY ON WRITE
	if (sz[1] != '-' && sz[2] == '-' && sz[3] == '-' && sz[4] == '-' && sz[5] == '-') { sz[1] = '-'; }
}

inline LPSTR vad_map_type(_In_ PVMMDLL_MAP_VADENTRY pVad)
{
	if (pVad->fImage)
		return (LPSTR)L"Image";
	else if (pVad->fFile)
		return (LPSTR)L"File ";
	else if (pVad->fHeap)
		return (LPSTR)L"Heap ";
	else if (pVad->fStack)
		return (LPSTR)L"Stack";
	else if (pVad->fTeb)
		return (LPSTR)L"Teb  ";
	else if (pVad->fPageFile)
		return (LPSTR)L"Pf   ";
	else
		return (LPSTR)L"     ";
}

struct module_data_t
{
	uint64_t base;
	uint32_t size;

	bool failed;
};

struct module_map_data_t
{
	uint64_t base;
	uint64_t pages;
	uint64_t page;
	bool is_wow64;
	uint32_t future_use;

	const char* text;

	uint32_t reserved;
	uint32_t software;
};

struct section_data_t
{
	uint64_t start, end;
	const char* name;
	uint32_t characteristics;
};

class c_memory
{
private:
	DWORD process_id = 0;

public:
	c_memory(DWORD in)
	{
		process_id = in;
	}

	DWORD get_pid()
	{
		return process_id;
	}

	void set_pid(DWORD in)
	{
		process_id = in;
	}

	std::vector<section_data_t> get_sections(LPSTR module_name);
	bool is_in_section(uint64_t address, section_data_t section_data);

	uint64_t find_signature(const char* signature, uint64_t range_start, uint64_t range_end);

	uint64_t string_scan(const char* str, uint64_t start, uint64_t end);

	/* return type -> template
	*  reads memory from template type at specified address
	*/
	template<typename t>
	inline t read(uint64_t address)
	{
		t data;
		VMMDLL_MemReadEx(handle, this->get_pid(), address, (PBYTE)&data, sizeof(data), 0, VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_NOPAGING | VMMDLL_FLAG_NOCACHEPUT | VMMDLL_FLAG_ZEROPAD_ON_FAIL | VMMDLL_FLAG_NOPAGING_IO);

		return data;
	}

	/* return type -> bool
	*  reads memory from template type at specified address to template buffer
	*/
	template<typename t>
	inline bool read_raw(uint64_t address, t buffer)
	{
		return VMMDLL_MemReadEx(handle, this->get_pid(), address, (PBYTE)buffer, sizeof(*buffer), 0, VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_NOPAGING | VMMDLL_FLAG_NOCACHEPUT | VMMDLL_FLAG_ZEROPAD_ON_FAIL | VMMDLL_FLAG_NOPAGING_IO);
	}

	/* return type -> bool
	*  writes to specified address with template type data
	*/
	template<typename t>
	inline bool write(uint64_t address, t data)
	{
		return VMMDLL_MemWrite(handle, this->get_pid(), address, (PBYTE)&data, sizeof(data));
	}

	/* return type -> bool
	*  writes to specified address with template type buffer
	*/
	template<typename t>
	inline bool write_raw(uint64_t address, t buffer)
	{
		return VMMDLL_MemWrite(handle, this->get_pid(), address, (PBYTE)buffer, sizeof(*buffer));
	}

	VMMDLL_SCATTER_HANDLE scatter_handle = NULL;
	int scatters = 0;

	void initialize_scatter();
	void uninitialize_scatter();

	/* return type -> template
	*  prepares a scatter at specified address
	*  second argument "ret" will be set as the return boolean
	*  returns default template on error
	*/
	template<typename t>
	t prepare_scatter(uint64_t address, bool* ret = nullptr)
	{
		if (!scatter_handle)
			return t();

		bool result = VMMDLL_Scatter_Prepare(scatter_handle, address, sizeof(t));
		if (ret)
			*ret = result;

		if (result)
			scatters++;
	}

	template<typename t>
	void prepare_scatter(uint64_t address, t buffer)
	{
		if (!scatter_handle)
			return;

		bool result = VMMDLL_Scatter_Prepare(scatter_handle, address, sizeof(buffer));

		if (result)
			scatters++;
	}

	/* return type -> bool
	*  dispatches a scatter read to the device
	*/
	bool dispatch_read()
	{
		if (!scatter_handle || scatters < 1)
			return false;

		return VMMDLL_Scatter_ExecuteRead(scatter_handle);
	}

	template<typename t>
	void prepare_write(uint64_t address, t buffer)
	{
		if (!scatter_handle)
			return;

		bool result = VMMDLL_Scatter_PrepareWrite(scatter_handle, address, (PBYTE)&buffer, sizeof(buffer));

		if (result)
			scatters++;
	}

	/* return type -> bool
	*  dispatches a scatter to the device including writes
	*/
	bool dispatch()
	{
		if (!scatter_handle || scatters < 1)
			return false;

		return VMMDLL_Scatter_Execute(scatter_handle);
	}

	template<typename t>
	t read_scatter(uint64_t address)
	{
		if (!scatter_handle || scatters < 1)
			return t();

		t result;

		DWORD callback = 0;
		BYTE byte_array[sizeof(t)];
		VMMDLL_Scatter_Read(scatter_handle, address, sizeof(t), byte_array, &callback);
		memcpy(&result, byte_array, sizeof(t));

		return result;
	}

	template<typename t>
	void read_scatter(uint64_t address, t buffer)
	{
		if (!scatter_handle || scatters < 1)
			return;

		DWORD callback = 0;
		BYTE byte_array[sizeof(t)];
		VMMDLL_Scatter_Read(scatter_handle, address, sizeof(t), byte_array, &callback);
		memcpy(&buffer, byte_array, sizeof(t));
	}
};

class c_process
{
private:
	DWORD process_id = 0;
public:
	bool failed = false;
	VMMDLL_PROCESS_INFORMATION information = {};

	c_process(const char* process_name);
	c_process(DWORD pid_in);

	DWORD get_pid()
	{
		return process_id;
	}

	void set_pid(DWORD in)
	{
		process_id = in;
	}

	module_data_t module_from_name(const char* module_name);
	std::vector<module_map_data_t> get_module_list();
	std::vector<PVMMDLL_MAP_HANDLEENTRY> get_handle_list();
	std::vector<VMMDLL_MAP_VADENTRY> get_map_list();
	c_memory get_memory();
};

struct user_map_data_t
{
	uint32_t future_use1[2];
	uint32_t future_use2[2];
	unsigned long long va_reg_hive;
	LPSTR usz_text, usz_sid;
	LPWSTR wsz_text, wsz_sid;
};

class c_registry
{
private:
	BYTE buffer[0x128];
	bool result;

public:
	c_registry(const char* path, DWORD type)
	{
		DWORD size = sizeof(buffer);
		result = VMMDLL_WinReg_QueryValueExU(handle, CC_TO_LPSTR(path), &type, buffer, &size);
		if (!result)
			printf("[-] failed QueryValueExU call\n");
	}

	const char* get()
	{
		return LPWSTR_TO_CC((LPWSTR)buffer);
	}

	int get_int()
	{
		int out;
		std::stringstream s(get());
		s >> out;

		return out;
	}

	bool get_result()
	{
		return result;
	}
};

struct machine_data_t
{
	int current_build;
	std::string edition;
	std::string display_version;
	std::string processor_name;
	std::string motherboard_manufacturer_name;
	std::string motherboard_name;
};

class c_device
{
private:
public:
	bool connected = false;

	uint64_t id = 0, major_version = 0, minor_version = 0;
	std::vector<const char*> o_args{};

	c_device(std::vector<const char*> c_args)
	{
		o_args = c_args;
	}

	bool connect();
	void disconnect();
	int error(const char* error);

	c_process process_from_name(const char* str);
	c_process process_from_pid(DWORD pid);
	std::vector<PVMMDLL_MAP_SERVICEENTRY> get_service_list();
	std::vector<user_map_data_t> get_users();
	std::vector<DWORD> get_pid_list();
	std::vector<c_process> get_process_list();
	machine_data_t get_machine_data();

	inline void keyboard()
	{
	}
};