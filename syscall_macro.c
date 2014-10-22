#define __SC_DECL1(t1, a1)	t1 a1
#define __SC_DECL2(t2, a2, ...) t2 a2, __SC_DECL1(__VA_ARGS__)
#define __SC_DECL3(t3, a3, ...) t3 a3, __SC_DECL2(__VA_ARGS__)
#define __SC_DECL4(t4, a4, ...) t4 a4, __SC_DECL3(__VA_ARGS__)
#define __SC_DECL5(t5, a5, ...) t5 a5, __SC_DECL4(__VA_ARGS__)
#define __SC_DECL6(t6, a6, ...) t6 a6, __SC_DECL5(__VA_ARGS__)

#ifdef CONFIG_HAVE_SYSCALL_WRAPPERS

#define SYSCALL_DEFINE(name) static inline long SYSC_##name

#define __SYSCALL_DEFINEx(x, name, ...)					\
	asmlinkage long sys##name(__SC_DECL##x(__VA_ARGS__));		\
	static inline long SYSC##name(__SC_DECL##x(__VA_ARGS__));	\
	asmlinkage long SyS##name(__SC_LONG##x(__VA_ARGS__))		\
	{								\
		__SC_TEST##x(__VA_ARGS__);				\
		return (long) SYSC##name(__SC_CAST##x(__VA_ARGS__));	\
	}								\
	SYSCALL_ALIAS(sys##name, SyS##name);				\
	static inline long SYSC##name(__SC_DECL##x(__VA_ARGS__))

#else /* CONFIG_HAVE_SYSCALL_WRAPPERS */

#define SYSCALL_DEFINE(name) asmlinkage long sys_##name
#define __SYSCALL_DEFINEx(x, name, ...)					\
	asmlinkage long sys##name(__SC_DECL##x(__VA_ARGS__))

#endif /* CONFIG_HAVE_SYSCALL_WRAPPERS */


#ifdef CONFIG_FTRACE_SYSCALLS
#define SYSCALL_DEFINEx(x, sname, ...)				\
	static const char *types_##sname[] = {			\
		__SC_STR_TDECL##x(__VA_ARGS__)			\
	};							\
	static const char *args_##sname[] = {			\
		__SC_STR_ADECL##x(__VA_ARGS__)			\
	};							\
	SYSCALL_METADATA(sname, x);				\
	__SYSCALL_DEFINEx(x, sname, __VA_ARGS__)
#else
#define SYSCALL_DEFINEx(x, sname, ...)				\
	__SYSCALL_DEFINEx(x, sname, __VA_ARGS__)
#endif

#ifdef CONFIG_FTRACE_SYSCALLS
#define __SC_STR_ADECL1(t, a)		#a
#define __SC_STR_ADECL2(t, a, ...)	#a, __SC_STR_ADECL1(__VA_ARGS__)
#define __SC_STR_ADECL3(t, a, ...)	#a, __SC_STR_ADECL2(__VA_ARGS__)
#define __SC_STR_ADECL4(t, a, ...)	#a, __SC_STR_ADECL3(__VA_ARGS__)
#define __SC_STR_ADECL5(t, a, ...)	#a, __SC_STR_ADECL4(__VA_ARGS__)
#define __SC_STR_ADECL6(t, a, ...)	#a, __SC_STR_ADECL5(__VA_ARGS__)

#define __SC_STR_TDECL1(t, a)		#t
#define __SC_STR_TDECL2(t, a, ...)	#t, __SC_STR_TDECL1(__VA_ARGS__)
#define __SC_STR_TDECL3(t, a, ...)	#t, __SC_STR_TDECL2(__VA_ARGS__)
#define __SC_STR_TDECL4(t, a, ...)	#t, __SC_STR_TDECL3(__VA_ARGS__)
#define __SC_STR_TDECL5(t, a, ...)	#t, __SC_STR_TDECL4(__VA_ARGS__)
#define __SC_STR_TDECL6(t, a, ...)	#t, __SC_STR_TDECL5(__VA_ARGS__)

#define SYSCALL_METADATA(sname, nb)				\
	static const struct syscall_metadata __used		\
	  __attribute__((__aligned__(4)))			\
	  __attribute__((section("__syscalls_metadata")))	\
	  __syscall_meta_##sname = {				\
		.name 		= "sys"#sname,			\
		.nb_args 	= nb,				\
		.types		= types_##sname,		\
		.args		= args_##sname,			\
	}

#define SYSCALL_DEFINE0(sname)					\
	static const struct syscall_metadata __used		\
	  __attribute__((__aligned__(4)))			\
	  __attribute__((section("__syscalls_metadata")))	\
	  __syscall_meta_##sname = {				\
		.name 		= "sys_"#sname,			\
		.nb_args 	= 0,				\
	};							\
	asmlinkage long sys_##sname(void)

#else
#define SYSCALL_DEFINE0(name)	   asmlinkage long sys_##name(void)
#endif
#define SYSCALL_DEFINE1(name, ...) SYSCALL_DEFINEx(1, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE2(name, ...) SYSCALL_DEFINEx(2, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE3(name, ...) SYSCALL_DEFINEx(3, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE4(name, ...) SYSCALL_DEFINEx(4, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE5(name, ...) SYSCALL_DEFINEx(5, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE6(name, ...) SYSCALL_DEFINEx(6, _##name, __VA_ARGS__)

SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol) 
{}