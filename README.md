# NtQuerySystemInformation Hook
By hooking the NtQuerySystemInformation function exported from Ntdll.dll, you can retrieve an array of SYSTEM_PROCESS_INFORMATION structures for each process in the system. You can iterate through this array and change the data in the structures or completely skip a structure, resulting in the process that is tied to that structure not showing up in applications that enumerate processes using NtQuerySystemInformation. This method can be used to hide malicious software from ever showing up in for example, Task Manager or Process Explorer. Compile as x64.

https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
