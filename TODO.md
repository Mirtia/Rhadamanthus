# TODO

## Do not forget
- [ ] Use context pointer to pass the dispatcher and check if the VM is paused, if not, then the state checks should not continue as they may perform the checks in an inconsistent state.
- [ ] Add test for idt that modifies all vcpu IDT.
- [ ] Write down clean requirements from Obsidian.

## TODO 22/08/2025 - 23/08/2025 -24/08/2025

- [x] Create new vm
- [x] Install tools (make and so on)
- [ ] Install correct kernel (2 different kernels - one for the old rootkits) and debug symbols
  - [x] 1 VM ubuntu-20-04 with 5.15.0-139 (io_uring requires 5.1+)
  - [-] 1 VM ubuntu-20-04 or 18-04 with  4.x or 3.x? A lot of the rootkits were compatible with old kernels.
  - [ ] Ubuntu 14 for older versions since the older kernels are not compatible with systemd new versions.
- [x] Update libvmi configurations /etc/libvmi.conf
  - [ ] Do for old
- [ ] Document every step
  - [ ] Also document the necessary packages needed for the new VM.
- [x] Create scripts for everything
- [ ] Add tty/console communication
- [x] Install python and necessary packages for Clueless-Admin
- [x] Take snapshots of clean states with all packages installed
  - [x] Only disk snapshots are required at this state
  - [x] On later stages both disk and memory snapshots are required
- [ ] Perform integrity check
- [x] State integrity callback
- [x] Test state integrity callback
- [ ] Test io_uring_artifacts with io_uring rootkit
- [x] Create first event_callback cr0 (easiest one)
  - [ ] Issue with finding pid of orgin
- [ ] Test cr0 write with idt_hook or any other rootkit

## TODO 22/08/2025 - ??

- [ ] Kernel code integrity is a stupid approach. It will only make sense when you compare at same alive boot. Compare along time window. Hold a history of the hashes.
- [ ] Double-check implementations so far and rationalize.
