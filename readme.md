# dse_hook

this project abuses a vulnerable driver called "winio64.sys"

we patch SeValidateImageData & SeValidateImageHeader to return zero. \
those functions are being used by ntoskrnl.exe when NtLoadDriver is called. \
by patching those functions we bypass the signature enforcement.

# but what about patchguard?
since patchguard only scans the system in random intervals, \
we have a small time-window to place a patch and remove it again. \
in that time we load our driver.

# perks
- bypasses KDP and PG(kinda).
- supports normal drivers (with driverobject).

# tested on
- Windows 10 22H2
- Windows 11 23H2
