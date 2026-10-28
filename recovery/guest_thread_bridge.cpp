/* Catch guest C++ exceptions before they unwind through the Windows host
 * pthread trampoline and q.so PE frames. The entry itself uses the host ABI;
 * only the invoked guest function uses SysV AMD64. */
#include <cstdio>

extern "C" void *hybris_guest_thread_call(void *fn, void *arg)
{
    using guest_fn = void *(__attribute__((sysv_abi)) *)(void *);
    try {
        return reinterpret_cast<guest_fn>(fn)(arg);
    } catch (...) {
        std::fprintf(stderr, "[guest-thread] caught guest exception\n");
        std::fflush(stderr);
        return nullptr;
    }
}
