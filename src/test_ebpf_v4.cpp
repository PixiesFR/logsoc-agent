/* test_ebpf_v4.cpp — Standalone test for V4.0 unified eBPF skeleton */
#include "ebpf/loader.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

static void sleep_ms(int ms)
{
    usleep(ms * 1000);
}

static bool drain_one_event(const char* label)
{
    char buf[512];
    int n = ebpf::poll(buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        std::printf("  [%s] EVENT: %s\n", label, buf);
        return true;
    }
    if (n == 0) {
        std::printf("  [%s] POLL=0 (stop requested)\n", label);
    } else {
        std::printf("  [%s] POLL=-1 (no data)\n", label);
    }
    return false;
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    std::printf("=== eBPF V4.0 Unified Skeleton Test ===\n");

    /* 1. Kernel check */
    std::printf("[1/5] kernel_ok() --> ");
    if (!ebpf::kernel_ok()) {
        std::printf("FAIL (%s)\n", ebpf::kernel_reason());
        return 1;
    }
    std::printf("OK (%s)\n", ebpf::kernel_reason());

    /* 2. Load + attach */
    std::printf("[2/5] ebpf::init()  --> ");
    if (!ebpf::init()) {
        std::printf("FAIL\n");
        return 1;
    }
    int fd = ebpf::get_fd();
    std::printf("OK (ringbuf fd=%d)\n", fd);

    /* 3. Trigger write event */
    std::printf("[3/5] Trigger __x64_sys_write (write stdout)...\n");
    (void)write(STDOUT_FILENO, "x", 1);   /* triggers kprobe */
    sleep_ms(150);
    drain_one_event("write");

    /* 4. Trigger execve event */
    std::printf("[4/5] Trigger __x64_sys_execve (/bin/true)...\n");
    pid_t pid = fork();
    if (pid == 0) {
        execl("/bin/true", "true", nullptr);
        _exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    }
    sleep_ms(150);
    drain_one_event("execve");

    /* 5. Cleanup */
    std::printf("[5/5] ebpf::stop()  --> ");
    ebpf::stop();
    std::printf("OK\n");

    std::printf("=== Test complete ===\n");
    return 0;
}
