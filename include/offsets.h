#ifndef OFFSETS_H
#define OFFSETS_H

#define LINUX_CRED_OFFSET        0XBA8
#define LINUX_STATE_OFFSET       0x18
#define LINUX_UID_OFFSET         0x4
#define LINUX_GID_OFFSET         0x8
#define LINUX_EUID_OFFSET        0x14
#define LINUX_EGID_OFFSET        0x18
#define LINUX_INET_HASHINFO_EHASH_OFFSET        0x0
#define LINUX_INET_HASHINFO_EHASH_MASK_OFFSET   0x10
#define LINUX_INET_HASHINFO_LHASH2_OFFSET       0x30
#define LINUX_SOCK_COMMON_OFFSET                0x0
#define LINUX_SKC_DADDR_OFFSET                  0x0
#define LINUX_SKC_RCV_SADDR_OFFSET              0x4
#define LINUX_SKC_DPORT_OFFSET                  0xC
#define LINUX_SKC_NUM_OFFSET                    0xE
#define LINUX_SKC_STATE_OFFSET                  0x12
#define LINUX_SKC_NODE_OFFSET                   0x68
#define LINUX_SKC_NODE_NEXT_OFFSET              0x0
#define LINUX_NET_NF_OFFSET                     0x40
#define LINUX_NF_HOOKS_OFFSET                   0x0

#define MODULE_LIST_OFFSET   0x08
#define MODULE_NAME_OFFSET   0x18
#define MODULE_STATE_OFFSET  0x00

#define LINUX_NETNF_HOOKS_IPV4_OFFSET   0x78
#define LINUX_NETNF_HOOKS_IPV6_OFFSET   0xA0
#define LINUX_NETNF_HOOKS_ARP_OFFSET    0xC8
#define LINUX_NETNF_HOOKS_BRIDGE_OFFSET 0xE0

#define NF_HOOK_ENTRIES_NUM_OFFSET 0x0
#define NF_HOOK_ENTRIES_PAD        0x8
#define NF_HOOK_ENTRY_SIZE         0x10


#endif // OFFSETS_H
