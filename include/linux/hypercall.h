#ifndef HYPERCALL_H
#define HYPERCALL_H
#include "linux/types.h"

static inline void igloo_hypercall(unsigned long num, unsigned long arg1) {
#if defined(CONFIG_MIPS)
    register unsigned long v0 asm("v0") = num;
    register unsigned long a0 asm("a0") = arg1;

    asm volatile(
       "movz $0, $0, $0"
        : "+r"(a0)  // Input and output in R0
        : "r"(v0), // num in register v0
        : // No clobber
    );


#elif defined(CONFIG_ARM)
  #if defined(CONFIG_ARM64)
  register uint32_t reg0 asm("x8") = num;
  register uint32_t reg1 asm("x0") = arg1;
  #else
  register uint32_t reg0 asm("r7") = num;
  register uint32_t reg1 asm("r0") = arg1;
  #endif
  

  asm volatile(
     "mov r0, %0 \t\n\
      mov r1, %1 \t\n\
      mcr p7, 0, r0, c0, c0, 0"
      :
      : "r"(reg0), "r"(reg1)
      :
  );
#else
#error "No igloo_hypercall support for architecture"
#endif
}

static inline unsigned long igloo_hypercall2(unsigned long num, unsigned long arg1, unsigned long arg2) {
#if defined(CONFIG_ARM)
   #if defined(CONFIG_ARM64)
  register uint32_t reg0 asm("x8") = num;
  register uint32_t reg1 asm("x0") = arg1;
  register uint32_t reg1 asm("x1") = arg2;
  #else
  register uint32_t reg0 asm("r7") = num;
  register uint32_t reg1 asm("r0") = arg1;
  register uint32_t reg2 asm("r0") = arg2;
  #endif

    asm volatile(
       "mcr p7, 0, r0, c0, c0, 0"
        : "+r"(reg1)  // Input and output
        : "r"(reg0), "r"(reg2),
        : // No clobber
    );

    return r0;

#elif defined(CONFIG_MIPS)
    register unsigned long v0 asm("v0") = num;
    register unsigned long a0 asm("a0") = arg1;
    register unsigned long a1 asm("a1") = arg2;

    asm volatile(
       "movz $0, $0, $0"
        : "+r"(a0)  // Input and output in R0
        : "r"(a1) , "r" (v0)// arg2 in register A1
        : // No clobber
    );
    return a0;

#else
    #error "No igloo_hypercall2 support for architecture"
#endif
}

#endif
