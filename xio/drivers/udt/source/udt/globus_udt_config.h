#ifndef GLOBUS_UDT_CONFIG_H
#define GLOBUS_UDT_CONFIG_H

#define UDT_EXPORTS

#if __APPLE__
        #define os OSX
        #if __ppc__
            #define arch PPC
        #elif __ppc64__
            #define arch PPC64
        #elif __i386__
            #define arch IA32
        #elif __x86_64__
            #define arch AMD64
        #else
            #error Unknown OSX architecture
        #endif
#elif __MINGW32__
        #define os WIN32
        #if __x86_64__
            #define arch AMD64
        #elif __i386__
            #define arch IA32
        #else
            #error Unknown windows architecture
        #endif
#elif __CYGWIN__
        #define os CYGWIN
        #if __x86_64__
            #define arch AMD64
        #elif __i386__
            #define arch IA32
        #else
            #error Unknown Cygwin architecture
        #endif
#elif __linux__
        #define os LINUX
        #if __x86_64__
            #define arch AMD64
        #elif __i386__
            #define arch IA32
        #else
            #error Unknown Linux architecture
        #endif
#else
        #error Unknown operating system
#endif

#endif /* GLOBUS_UDT_CONFIG_H */
