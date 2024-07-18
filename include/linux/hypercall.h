#ifndef HYPERCALL_H
#define HYPERCALL_H
#include "linux/types.h"

static inline void igloo_hypercall(unsigned long num, unsigned long arg1) {
#if defined(CONFIG_MIPS)
    register unsigned long reg0 asm("v0") = num;
    register unsigned long reg1 asm("a0") = arg1;

    asm volatile(
       "movz $0, $0, $0"
        :
        : "r"(reg0), "r"(reg1) // num in register v0
        : // No clobber
    );


#elif defined(CONFIG_ARM64)
    register unsigned long reg0 asm("x8") = num;
    register unsigned long reg1 asm("x0") = arg1;
    asm volatile(
            "msr S0_0_c5_c0_0, xzr \n"
            :
            : "r"(reg0), "r"(reg1)
            : // No clobber
        );
  #elif defined(CONFIG_ARM) 
    register unsigned long reg0 asm("r7") = num;
    register unsigned long reg1 asm("r0") = arg1;

    asm volatile(
    "mcr p7, 0, r0, c0, c0, 0"
      :
      : "r"(reg0), "r"(reg1)
      :
  );  
#else
#error "No igloo_hypercall support for architecture"
#endif
}

static inline unsigned long igloo_hypercall2(unsigned long num, unsigned long arg1, unsigned long arg2) {
#if defined(CONFIG_ARM64)
    register unsigned long reg0 asm("x8") = num;
    register unsigned long reg1 asm("x0") = arg1;
    register unsigned long reg2 asm("x1") = arg2;
    asm volatile(
       "msr S0_0_c5_c0_0, xzr \n"
        : "+r"(reg1)  // Input and output
        : "r"(reg0), "r"(reg2)
        : // No clobber
    );
    return reg1;
#elif defined(CONFIG_ARM)
    register unsigned long reg0 asm("r7") = num;
    register unsigned long reg1 asm("r0") = arg1;
    register unsigned long reg2 asm("r1") = arg2;

    asm volatile(
       "mcr p7, 0, r0, c0, c0, 0"
        : "+r"(reg1)  // Input and output
        : "r"(reg0), "r"(reg2)
        : // No clobber
    );



    return reg1;

#elif defined(CONFIG_MIPS)
    register unsigned long reg0 asm("v0") = num;
    register unsigned long reg1 asm("a0") = arg1;
    register unsigned long reg2 asm("a1") = arg2;

    asm volatile(
       "movz $0, $0, $0"
        : "+r"(reg0)  // Input and output in R0
        : "r"(reg1) , "r" (reg2)// arg2 in register A1
        : // No clobber
    );
    return reg0;

#else
    #error "No igloo_hypercall2 support for architecture"
#endif
}

#endif
