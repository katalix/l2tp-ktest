// https://syzkaller.appspot.com/bug?id=d2c64e2d7c308cce1b51fd51addd4284cd825792
// autogenerated by syzkaller (https://github.com/google/syzkaller)

#define _GNU_SOURCE

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <linux/capability.h>

static bool write_file(const char* file, const char* what, ...)
{
  char buf[1024];
  va_list args;
  va_start(args, what);
  vsnprintf(buf, sizeof(buf), what, args);
  va_end(args);
  buf[sizeof(buf) - 1] = 0;
  int len = strlen(buf);
  int fd = open(file, O_WRONLY | O_CLOEXEC);
  if (fd == -1)
    return false;
  if (write(fd, buf, len) != len) {
    int err = errno;
    close(fd);
    errno = err;
    return false;
  }
  close(fd);
  return true;
}

#define MAX_FDS 30

static void setup_common()
{
  if (mount(0, "/sys/fs/fuse/connections", "fusectl", 0, 0)) {
  }
}

static void loop();

static void sandbox_common()
{
  prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
  setpgrp();
  setsid();
  struct rlimit rlim;
  rlim.rlim_cur = rlim.rlim_max = (200 << 20);
  setrlimit(RLIMIT_AS, &rlim);
  rlim.rlim_cur = rlim.rlim_max = 32 << 20;
  setrlimit(RLIMIT_MEMLOCK, &rlim);
  rlim.rlim_cur = rlim.rlim_max = 136 << 20;
  setrlimit(RLIMIT_FSIZE, &rlim);
  rlim.rlim_cur = rlim.rlim_max = 1 << 20;
  setrlimit(RLIMIT_STACK, &rlim);
  rlim.rlim_cur = rlim.rlim_max = 0;
  setrlimit(RLIMIT_CORE, &rlim);
  rlim.rlim_cur = rlim.rlim_max = 256;
  setrlimit(RLIMIT_NOFILE, &rlim);
  if (unshare(CLONE_NEWNS)) {
  }
  if (unshare(CLONE_NEWIPC)) {
  }
  if (unshare(0x02000000)) {
  }
  if (unshare(CLONE_NEWUTS)) {
  }
  if (unshare(CLONE_SYSVSEM)) {
  }
  typedef struct {
    const char* name;
    const char* value;
  } sysctl_t;
  static const sysctl_t sysctls[] = {
      {"/proc/sys/kernel/shmmax", "16777216"},
      {"/proc/sys/kernel/shmall", "536870912"},
      {"/proc/sys/kernel/shmmni", "1024"},
      {"/proc/sys/kernel/msgmax", "8192"},
      {"/proc/sys/kernel/msgmni", "1024"},
      {"/proc/sys/kernel/msgmnb", "1024"},
      {"/proc/sys/kernel/sem", "1024 1048576 500 1024"},
  };
  unsigned i;
  for (i = 0; i < sizeof(sysctls) / sizeof(sysctls[0]); i++)
    write_file(sysctls[i].name, sysctls[i].value);
}

static int wait_for_loop(int pid)
{
  if (pid < 0)
    exit(1);
  int status = 0;
  while (waitpid(-1, &status, __WALL) != pid) {
  }
  return WEXITSTATUS(status);
}

static void drop_caps(void)
{
  struct __user_cap_header_struct cap_hdr = {};
  struct __user_cap_data_struct cap_data[2] = {};
  cap_hdr.version = _LINUX_CAPABILITY_VERSION_3;
  cap_hdr.pid = getpid();
  if (syscall(SYS_capget, &cap_hdr, &cap_data))
    exit(1);
  const int drop = (1 << CAP_SYS_PTRACE) | (1 << CAP_SYS_NICE);
  cap_data[0].effective &= ~drop;
  cap_data[0].permitted &= ~drop;
  cap_data[0].inheritable &= ~drop;
  if (syscall(SYS_capset, &cap_hdr, &cap_data))
    exit(1);
}

static int do_sandbox_none(void)
{
  if (unshare(CLONE_NEWPID)) {
  }
  int pid = fork();
  if (pid != 0)
    return wait_for_loop(pid);
  setup_common();
  sandbox_common();
  drop_caps();
  if (unshare(CLONE_NEWNET)) {
  }
  loop();
  exit(1);
}

static void close_fds()
{
  int fd;
  for (fd = 3; fd < MAX_FDS; fd++)
    close(fd);
}

uint64_t r[2] = {0xffffffffffffffff, 0xffffffffffffffff};

void loop(void)
{
  intptr_t res = 0;
  res = syscall(__NR_socket, 0x18ul, 1ul, 1);
  if (res != -1)
    r[0] = res;
  res = syscall(__NR_socket, 0xaul, 0x80002ul, 0);
  if (res != -1)
    r[1] = res;
  *(uint32_t*)0x20000180 = 0xb;
  syscall(__NR_setsockopt, r[1], 1, 0xf, 0x20000180ul, 4ul);
  *(uint16_t*)0x20f5dfe4 = 0xa;
  *(uint16_t*)0x20f5dfe6 = htobe16(0x4e20);
  *(uint32_t*)0x20f5dfe8 = htobe32(0);
  *(uint8_t*)0x20f5dfec = 0;
  *(uint8_t*)0x20f5dfed = 0;
  *(uint8_t*)0x20f5dfee = 0;
  *(uint8_t*)0x20f5dfef = 0;
  *(uint8_t*)0x20f5dff0 = 0;
  *(uint8_t*)0x20f5dff1 = 0;
  *(uint8_t*)0x20f5dff2 = 0;
  *(uint8_t*)0x20f5dff3 = 0;
  *(uint8_t*)0x20f5dff4 = 0;
  *(uint8_t*)0x20f5dff5 = 0;
  *(uint8_t*)0x20f5dff6 = 0;
  *(uint8_t*)0x20f5dff7 = 0;
  *(uint8_t*)0x20f5dff8 = 0;
  *(uint8_t*)0x20f5dff9 = 0;
  *(uint8_t*)0x20f5dffa = 0;
  *(uint8_t*)0x20f5dffb = 0;
  *(uint32_t*)0x20f5dffc = 0;
  syscall(__NR_bind, r[1], 0x20f5dfe4ul, 0x1cul);
  *(uint16_t*)0x200001c0 = 0x18;
  *(uint32_t*)0x200001c2 = 1;
  *(uint32_t*)0x200001c6 = 0;
  *(uint32_t*)0x200001ca = r[1];
  *(uint32_t*)0x200001ce = 1;
  *(uint32_t*)0x200001d2 = 0;
  *(uint32_t*)0x200001d6 = 1;
  *(uint32_t*)0x200001da = 0;
  *(uint16_t*)0x200001de = 0xa;
  *(uint16_t*)0x200001e0 = htobe16(0x4e20);
  *(uint32_t*)0x200001e2 = htobe32(7);
  *(uint8_t*)0x200001e6 = 0;
  *(uint8_t*)0x200001e7 = 0;
  *(uint8_t*)0x200001e8 = 0;
  *(uint8_t*)0x200001e9 = 0;
  *(uint8_t*)0x200001ea = 0;
  *(uint8_t*)0x200001eb = 0;
  *(uint8_t*)0x200001ec = 0;
  *(uint8_t*)0x200001ed = 0;
  *(uint8_t*)0x200001ee = 0;
  *(uint8_t*)0x200001ef = 0;
  *(uint8_t*)0x200001f0 = -1;
  *(uint8_t*)0x200001f1 = -1;
  *(uint8_t*)0x200001f2 = 0xac;
  *(uint8_t*)0x200001f3 = 0x14;
  *(uint8_t*)0x200001f4 = 0x14;
  *(uint8_t*)0x200001f5 = 0x12;
  *(uint32_t*)0x200001f6 = 0x3ff;
  syscall(__NR_connect, r[0], 0x200001c0ul, 0x3aul);
  close_fds();
}
int main(void)
{
  syscall(__NR_mmap, 0x1ffff000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);
  syscall(__NR_mmap, 0x20000000ul, 0x1000000ul, 7ul, 0x32ul, -1, 0ul);
  syscall(__NR_mmap, 0x21000000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);
  do_sandbox_none();
  return 0;
}
