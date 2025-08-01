/* SPDX-License-Identifier: GPL-2.0 */
/*
 * syscall_wrapper.h - arm64 specific wrappers to syscall definitions
 *
 * Based on arch/x86/include/asm_syscall_wrapper.h
 */

#ifndef __ASM_SYSCALL_WRAPPER_H
#define __ASM_SYSCALL_WRAPPER_H

#include <asm/ptrace.h>
// === Igloo Interception Support ===
#include <igloo_syscall_macros.h>

#ifdef CONFIG_IGLOO
extern igloo_syscall_enter_t igloo_syscall_enter_hook;
extern igloo_syscall_return_t igloo_syscall_return_hook;
#endif

#define SC_ARM64_REGS_TO_ARGS(x, ...)				\
	__MAP(x,__SC_ARGS					\
	      ,,regs->regs[0],,regs->regs[1],,regs->regs[2]	\
	      ,,regs->regs[3],,regs->regs[4],,regs->regs[5])

#ifdef CONFIG_COMPAT

#define COMPAT_SYSCALL_DEFINEx(x, name, ...)						\
	asmlinkage long __arm64_compat_sys##name(const struct pt_regs *regs);		\
	ALLOW_ERROR_INJECTION(__arm64_compat_sys##name, ERRNO);				\
	void __igloo_set_args_compat##name(const unsigned long args_ptr_array[], const __le64 new_args_le64[]); \
	void __igloo_set_args_compat##name(const unsigned long args_ptr_array[], const __le64 new_args_le64[]) \
	{ __SC_GEN_SETTER_BODY_WRAPPER(x, __VA_ARGS__); }					\
	static long __se_compat_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__));		\
	static inline long __do_compat_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));	\
	asmlinkage long __arm64_compat_sys##name(const struct pt_regs *regs)		\
	{										\
		return __se_compat_sys##name(SC_ARM64_REGS_TO_ARGS(x,__VA_ARGS__));	\
	}										\
	static long __se_compat_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__))		\
	{										\
		long ret;								\
		bool skip = false;							\
		long skip_ret = 0;							\
		unsigned long args_ptr_array[IGLOO_SYSCALL_MAXARGS] = {0};		\
		__SC_ASSIGN_ADDR_WRAPPER(x, args_ptr_array, __VA_ARGS__);		\
		/* Igloo enter hook */							\
		if (igloo_syscall_enter_hook) {					\
			skip = igloo_syscall_enter_hook(__stringify(name), &skip_ret, x,	\
				args_ptr_array, __igloo_set_args_compat##name);		\
		}									\
		if (skip) {								\
			ret = skip_ret;							\
		} else {								\
			ret = __do_compat_sys##name(__MAP(x,__SC_DELOUSE,__VA_ARGS__));	\
		}									\
		/* Igloo return hook */							\
		if (igloo_syscall_return_hook) {					\
			ret = igloo_syscall_return_hook(__stringify(name), ret, x, args_ptr_array); \
		}									\
		return ret;								\
	}										\
	static inline long __do_compat_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))

#define COMPAT_SYSCALL_DEFINE0(sname)							\
	asmlinkage long __arm64_compat_sys_##sname(const struct pt_regs *__unused);	\
	ALLOW_ERROR_INJECTION(__arm64_compat_sys_##sname, ERRNO);			\
	asmlinkage long __arm64_compat_sys_##sname(const struct pt_regs *__unused)

#define COND_SYSCALL_COMPAT(name) 							\
	asmlinkage long __arm64_compat_sys_##name(const struct pt_regs *regs);		\
	asmlinkage long __weak __arm64_compat_sys_##name(const struct pt_regs *regs)	\
	{										\
		return sys_ni_syscall();						\
	}

#endif /* CONFIG_COMPAT */

#define __SYSCALL_DEFINEx(x, name, ...)						\
	asmlinkage long __arm64_sys##name(const struct pt_regs *regs);		\
	ALLOW_ERROR_INJECTION(__arm64_sys##name, ERRNO);			\
	void __igloo_set_args##name(const unsigned long args_ptr_array[], const __le64 new_args_le64[]); \
	void __igloo_set_args##name(const unsigned long args_ptr_array[], const __le64 new_args_le64[]) \
	{ __SC_GEN_SETTER_BODY_WRAPPER(x, __VA_ARGS__); }					\
	static long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__));		\
	static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));	\
	asmlinkage long __arm64_sys##name(const struct pt_regs *regs)		\
	{									\
		return __se_sys##name(SC_ARM64_REGS_TO_ARGS(x,__VA_ARGS__));	\
	}									\
	static long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__))		\
	{									\
		long ret;								\
		bool skip = false;							\
		long skip_ret = 0;							\
		unsigned long args_ptr_array[IGLOO_SYSCALL_MAXARGS] = {0};		\
		__SC_ASSIGN_ADDR_WRAPPER(x, args_ptr_array, __VA_ARGS__);		\
		/* Igloo enter hook */							\
		if (igloo_syscall_enter_hook) {					\
			skip = igloo_syscall_enter_hook(__stringify(name), &skip_ret, x,	\
				args_ptr_array, __igloo_set_args##name);		\
		}									\
		if (skip) {								\
			ret = skip_ret;							\
		} else {								\
			ret = __do_sys##name(__MAP(x,__SC_CAST,__VA_ARGS__));	\
		}									\
		/* Igloo return hook */							\
		if (igloo_syscall_return_hook) {					\
			ret = igloo_syscall_return_hook(__stringify(name), ret, x, args_ptr_array); \
		}									\
		__MAP(x,__SC_TEST,__VA_ARGS__);					\
		__PROTECT(x, ret,__MAP(x,__SC_ARGS,__VA_ARGS__));		\
		return ret;							\
	}									\
	static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))

#define SYSCALL_DEFINE0(sname)							\
	SYSCALL_METADATA(_##sname, 0);						\
	asmlinkage long __arm64_sys_##sname(const struct pt_regs *__unused);	\
	ALLOW_ERROR_INJECTION(__arm64_sys_##sname, ERRNO);			\
	asmlinkage long __arm64_sys_##sname(const struct pt_regs *__unused)

#define COND_SYSCALL(name)							\
	asmlinkage long __arm64_sys_##name(const struct pt_regs *regs);		\
	asmlinkage long __weak __arm64_sys_##name(const struct pt_regs *regs)	\
	{									\
		return sys_ni_syscall();					\
	}

asmlinkage long __arm64_sys_ni_syscall(const struct pt_regs *__unused);

#endif /* __ASM_SYSCALL_WRAPPER_H */
