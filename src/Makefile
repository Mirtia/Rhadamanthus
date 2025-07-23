CC = gcc
CC_FLAGS = -g
LIBS = -lvmi -lm
OPENSSL_LIBS = -lcrypto

RM = rm -rf

MAIN = vmi
PROCESS_LIST = process-list
MODULE_LIST = module-list
SYSCALL_CHECK = syscall-check
IDT_CHECK = idt-check
NETWORK_CHECK = network-check
PROCFS_CHECK = procfs-check
SYSCALL_TRACE = syscall-trace
SOCKETAPI_TRACE = socketapi-trace
DRIVERAPI_TRACE = driverapi-trace
PROCESS_BLOCK = process-block
SLEEPAPI_NOP = sleepapi-nop
PROCESS_KILL = process-kill
UTILS = utils

OBJECTS = $(MAIN).o $(PROCESS_LIST).o $(MODULE_LIST).o $(SYSCALL_CHECK).o \
        $(IDT_CHECK).o $(NETWORK_CHECK).o $(PROCFS_CHECK).o $(SYSCALL_TRACE).o \
				$(UTILS).o
				
$(MAIN): $(OBJECTS)
	$(CC) $(CC_FLAGS) -o $(MAIN) $(OBJECTS) $(LIBS) $(OPENSSL_LIBS)

$(OBJECTS): $(MAIN).h $(UTILS).h

.PHONE: clean
clean:
	$(RM) $(MAIN) $(OBJECTS)
