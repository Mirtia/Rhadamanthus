# Data

## interrupt_index.linux

This file is identical to the file provided in [Cloud_Integrity](https://github.com/tianweiz07/Cloud_Integrity). It is used in the state callback `idt_table`.

**File:** [`data/interrupt_index.linux`](../data/interrupt_index.linux)  
**Used by:** [`src/state_callbacks/idt_table.c`](../src/state_callbacks/idt_table.c)

## known_files.linux

This list contains files and directories observed in rootkit samples. This has not been filled out yet since the callback has not been implemented.

**File:** [`data/known_files.linux`](../data/known_files.linux)  
**Used by:** [`src/state_callbacks/dir_string_matching.c`](../src/state_callbacks/dir_string_matching.c)

## syscall_index.linux

This file is identical to the file provided by [Cloud_Integrity](https://github.com/tianweiz07/Cloud_Integrity). It is used by the state callback `syscall_table`.

**File:** [`data/syscall_index.linux`](../data/syscall_index.linux)  
**Used by:** [`src/state_callbacks/syscall_table.c`](../src/state_callbacks/syscall_table.c)
