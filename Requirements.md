# Requirements

## General

All responses should be saved in *JSON* format.

## ftrace

The most well-known method used by kernel-mode rootkits lately, as modifying the system call table is not viable anymore, with newer kernels is using *ftrace* with probes to hook system calls. Example code for registering hooks can be found in this repository.