#include <asm/desc.h>
#include <asm/unistd.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/smp.h>
#include <linux/types.h>
#include <linux/version.h>

/**
 * @brief  Structure representing an IDT entry for x86_64 architecture.
 */
struct idt_entry64 {
  uint16_t offset_low;  ///< Handler RIP bits 15:0.
  uint16_t
      selector;  ///< Code-segment selector in GDT/LDT (e.g., __KERNEL_CS for kernel handlers).
  uint8_t
      ist;  ///< Interrupt Stack Table index in bits 0–2 (0 = no IST switch). Bits 3–7 must be 0.
  uint8_t type_attr;  ///< Gate type/attributes:
                      ///<   bit 7: P (Present);
                      ///<   bits 6–5: DPL;
                      ///<   bit 4: 0 (must be zero for interrupt/trap gates);
      ///<   bits 3–0: gate type (0xE = 64-bit interrupt gate, 0xF = 64-bit trap gate).
  uint16_t offset_middle;  ///< Handler RIP bits 31:16.
  uint32_t offset_high;    ///< Handler RIP bits 63:32.
  uint32_t zero;           ///< Reserved; must be zero.
} __attribute__((packed));

static struct desc_ptr idtr;
static struct idt_entry64 original_entry;
static void* original_handler = NULL;

/**
 * @brief Writes CR0 with WP bit cleared/set.
 * @param val Value to write to CR0.
 */
static inline void write_cr0_forced(unsigned long val) {
  unsigned long __force_order;
  asm volatile("mov %0, %%cr0" : "+r"(val), "+m"(__force_order));
}

/**
 * @brief Reconstructs 64-bit interrupt handler address from IDT entry.
 * @param vector Interrupt vector number.
 */
static void* get_interrupt_from_idt(int vector) {
  struct idt_entry64* idt = (struct idt_entry64*)idtr.address;

  uint64_t offset = ((uint64_t)idt[vector].offset_high << 32) |
                    ((uint64_t)idt[vector].offset_middle << 16) |
                    ((uint64_t)idt[vector].offset_low);

  return (void*)offset;
}

/**
 * @brief Custom handler for int 0x80.
 */
__attribute__((interrupt)) static void int80_hook(struct pt_regs* regs) {
  printk(KERN_ALERT "[*] int 0x80 hooked handler triggered.\n");

  // Chain to original handler.
  if (original_handler) {
    asm volatile(
        "cli\n\t"
        "jmp *%0"
        :
        : "r"(original_handler));
  }

  // If halt as fallback, won't cpu core freeze?
  // asm volatile("cli; hlt");
}

/**
 * @brief Module initialization.
 */
static int __init idt_hook_init(void) {
  store_idt(&idtr);
  printk(KERN_ALERT "[*] IDT base address: 0x%llx\n",
         (unsigned long long)idtr.address);

  struct idt_entry64* idt = (struct idt_entry64*)idtr.address;
  original_entry = idt[0x80];
  original_handler = get_interrupt_from_idt(0x80);

  printk(KERN_ALERT "[*] Original int 0x80 handler address: %p\n",
         original_handler);

  unsigned long new_addr = (unsigned long)int80_hook;
  unsigned long cr0 = read_cr0();

  write_cr0_forced(cr0 & ~0x00010000);

  idt[0x80].offset_low = new_addr & 0xFFFF;
  idt[0x80].offset_middle = (new_addr >> 16) & 0xFFFF;
  idt[0x80].offset_high = (new_addr >> 32) & 0xFFFFFFFF;

  write_cr0_forced(cr0 | 0x00010000);

  printk(KERN_ALERT "[*] int 0x80 hook installed.\n");
  return 0;
}

/**
 * @brief Module cleanup.
 */
static void __exit idt_hook_exit(void) {
  struct idt_entry64* idt = (struct idt_entry64*)idtr.address;
  unsigned long cr0 = read_cr0();

  write_cr0_forced(cr0 & ~0x00010000);
  idt[0x80] = original_entry;
  write_cr0_forced(cr0 | 0x00010000);

  printk(KERN_ALERT "[*] Restored original int 0x80 handler.\n");
}

module_init(idt_hook_init);
module_exit(idt_hook_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("mirtia");
MODULE_DESCRIPTION(
    "Hook int 0x80 handler via IDT modification (x86_64). Inspired by Calvin's "
    "syscall idt hook.");
