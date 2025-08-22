# TODO

## Do not forget
- [ ] Use context pointer to pass the dispatcher and check if the VM is paused, if not, then the state checks should not continue as they may perform the checks in an inconsistent state.
- [ ] Add test for idt that modifies all vcpu IDT.
- [ ] Write down clean requirements from Obsidian.

## TODO 22/08/2025

- [ ] Create new vm 
- [ ] Install tools (make and so on)
- [ ] Install correct kernel (2 different kernels - one for the old rootkits) and debug symbols
  - [ ] 1 VM ubuntu-20-04 with 5.15.0-139 (io_uring requires 5.1+)
  - [ ] 1 VM ubuntu-20-04 or 18-04 with  4.x or 3.x? A lot of the rootkits were compatible with old kernels.
- [ ] Update libvmi configurations /etc/libvmi.conf
- [ ] Document every step
- [ ] Create scripts for everything
- [ ] Add tty/console communication
- [ ] Install python and necessary packages for Clueless-Admin
- [ ] Take snapshots of clean states
- [ ] Perform integrity check
- [ ] State integrity callback
- [ ] Test state integrity callback
- [ ] Test io_uring_artifacts with io_uring rootkit
- [ ] Create first event_callback cr0 (easiest one)
- [ ] Test cr0 write with idt_hook or any other rootkit



