#ifndef HYPERCALL_H
#define HYPERCALL_H

static inline void igloo_hypercall(uint64_t num, uint64_t arg1) {
#ifdef CONFIG_MIPS
    register unsigned long a0 asm("a0") = num;
    register unsigned long a1 asm("a1") = arg1;

    asm volatile(
       "movz $0, $0, $0"
        : "+r"(a0)  // Input and output in R0
        : "r"(a1) // arg1 in register A1
        : // No clobber
    );


#elif defined(CONFIG_ARM)
  register uint32_t r0 asm("r0") = num;
  register uint32_t r1 asm("r1") = arg1;
  asm volatile(
     "mov r0, %0 \t\n\
      mov r1, %1 \t\n\
      mcr p7, 0, r0, c0, c0, 0"
      :
      : "r"(r0), "r"(r1)
      :
  );
#else
#error "No igloo_hypercall support for architecture"
#endif
}

static inline unsigned long igloo_hypercall2(uint64_t num, uint64_t arg1, uint64_t arg2) {
#if defined(CONFIG_ARM)
  register uint32_t r0 asm("r0") = num;  // Set up r0 with the value of num
  register uint32_t r1 asm("r1") = a1;   // Argument 2
  register uint32_t r2 asm("r2") = a2;   // Argument 3

  asm volatile(
     "mcr p7, 0, r0, c0, c0, 0"
      : "+r"(r0)  // Input and output
      : "r"(r1), "r"(r2)
      :  // Clobber list is empty because r0 is specified as an input-output operand
  );

  // Read the result from r0
  return r0;
#else
#error "No igloo_hypercall2 support for architecture"
#endif
}

#endif
