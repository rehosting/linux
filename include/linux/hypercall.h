#ifndef HYPERCALL_H
#define HYPERCALL_H
#include "linux/types.h"

static inline void igloo_hypercall(uint64_t num, uint64_t arg1) {
#if defined(CONFIG_MIPS) && defined(CONFIG_64BIT)
    // XXX shouldn't 'unsigned long' type work for both 32 and 64 bit?
    // Do we actually need both cases?
    register unsigned long long a0 asm("a0") = num;
    register unsigned long long a1 asm("a1") = arg1;

    asm volatile(
       "movz $0, $0, $0"
        : "+r"(a0)  // Input and output in R0
        : "r"(a1) // arg1 in register A1
        : // No clobber
    );

#elif defined(CONFIG_MIPS) && !defined(CONFIG_64BIT)
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
    register unsigned long r0 asm("r0") = num;
    register unsigned long r1 asm("r1") = arg1;
    register unsigned long r2 asm("r2") = arg2;

    asm volatile(
       "mcr p7, 0, r0, c0, c0, 0"
        : "+r"(r0)  // Input and output
        : "r"(r1), "r"(r2)
        : // No clobber
    );

    return r0;

#elif defined(CONFIG_MIPS) && defined(CONFIG_64BIT)
    register unsigned long long a0 asm("a0") = num;
    register unsigned long long a1 asm("a1") = arg1;
    register unsigned long long a2 asm("a2") = arg2;

    asm volatile(
       "movz $0, $0, $0"
        : "+r"(a0)  // Input and output in R0
        : "r"(a1) , "r" (a2)// arg1 in register A1
        : // No clobber
    );

#elif defined(CONFIG_MIPS) && !defined(CONFIG_64BIT)
    register unsigned long a0 asm("a0") = num;
    register unsigned long a1 asm("a1") = arg1;
    register unsigned long a2 asm("a2") = arg2;

    asm volatile(
       "movz $0, $0, $0"
        : "+r"(a0)  // Input and output in R0
        : "r"(a1), "r"(a2) // arg1 in register A1, arg2 in register A2
        : // No clobber
    );
    return a0;

#else
    #error "No igloo_hypercall2 support for architecture"
#endif
}

#endif
