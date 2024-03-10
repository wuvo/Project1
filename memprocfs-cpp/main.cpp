#include "functions.h"

int main()
{
    std::vector<const char*> args = { "", "-device", "FPGA" };

    c_device device = c_device(args);
    if (!device.connect())
        return device.error("[-] failed to connect to device\n");
    else
        printf("[+] connected to device, id -> %lli | version -> %lli.%lli\n\n", device.id, device.major_version, device.minor_version);

    c_process process = device.process_from_name("RelicCardinal.exe");
    if (process.failed)
        return device.error("[-] failed to find RelicCardinal\n");
    else
        printf("[+] found relicCardinal\n");

    module_data_t assembly = process.module_from_name("RelicCardinal.exe");
    if (assembly.failed)
        return device.error("[-] failed to find assembly\n");
    else
        printf("[+] found assembly, base -> 0x%llx | size -> 0x%llx\n", assembly.base, assembly.size);

    c_memory memory = process.get_memory();

    // First address (Steam replay no fov toggle)
    unsigned char FOV1 = memory.read<unsigned char>(assembly.base + 0x79ACFE8);
    printf("[+] Value Was %d Changing to 1  \n", FOV1);
    memory.write<unsigned char>(assembly.base + 0x79ACFE8, 1);

    // Base address
    uintptr_t base = assembly.base + 0x83129A0;

    // First step of the pointer chain
    uintptr_t address1 = memory.read<uintptr_t>(base);
    printf("[+] First step of the pointer chain, address1 -> 0x%llx\n", address1);

    // Second step of the pointer chain
    uintptr_t address2 = memory.read<uintptr_t>(address1 + 0x0);
    printf("[+] Second step of the pointer chain, address2 -> 0x%llx\n", address2);

    // Third step of the pointer chain
    uintptr_t address3 = memory.read<uintptr_t>(address2 + 0x2718);
    printf("[+] Third step of the pointer chain, address3 -> 0x%llx\n", address3);

    uintptr_t finaladdress = address3 + 0x2AC;
    printf("[+] Final Step of the pointer chain, Final Address -> 0x%llx\n", finaladdress);

    unsigned char finalvalue = memory.read<unsigned char>(finaladdress);
    printf("[+] Value before update, address -> 0x%llx, value -> %d\n", finaladdress, finalvalue);

    memory.write<unsigned char>(finaladdress, 0);
    printf("[+] Value updated and should be 0 it is currently %d\n", memory.read<unsigned char>(finaladdress));

    device.disconnect();
    printf("[+] disconnected device\n");

    getchar();
    return 0;
}
