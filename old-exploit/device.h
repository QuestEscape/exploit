// Emulator
// Virtual kernel memory layout:
//     modules : 0xffffff8000000000 - 0xffffff8008000000   (   128 MB)
//     vmalloc : 0xffffff8008000000 - 0xffffffbdbfff0000   (   246 GB)
//       .init : 0xffffff80087b5000 - 0xffffff8008813000   (   376 KB)
//       .text : 0xffffff8008080000 - 0xffffff8008634000   (  5840 KB)
//     .rodata : 0xffffff8008634000 - 0xffffff80087b5000   (  1540 KB)
//       .data : 0xffffff8008813000 - 0xffffff8008869c00   (   347 KB)
//     vmemmap : 0xffffffbdc0000000 - 0xffffffbfc0000000   (     8 GB maximum)
//               0xffffffbdc0000000 - 0xffffffbdc1000000   (    16 MB actual)
//     fixed   : 0xffffffbffe7fb000 - 0xffffffbffec00000   (  4116 KB)
//     PCI I/O : 0xffffffbffee00000 - 0xffffffbfffe00000   (    16 MB)
//     memory  : 0xffffffc000000000 - 0xffffffc040000000   (  1024 MB)

/*#define DUMP_BEG 0xffffff8008634000
#define DUMP_END 0xffffff80087b5000

#define TESTER 0xFFFFFF80086A0900

#define OFFSETOF_SKC_PROT 0x28
#define OFFSETOF_IOCTL 0x20
#define OFFSETOF_GETSOCKOPT 0x70
#define KERNEL_GETSOCKOPT 0xFFFFFF8008444F6C
#define INET6_IOCTL_END 0xFFFFFF8008540E34

#define INIT_TASK 0xffffff8008828440
#define SELINUX_ENABLED 0xffffff8008840998
#define SELINUX_ENFORCING 0xffffff80088a9234

#define HAS_PTRACE 1
#undef CONFIG_KEYS
#define CONFIG_SECURITY 1*/

// Oculus Quest - 213561.4150.0
// [    0.000000] Virtual kernel memory layout:
// [    0.000000]     modules : 0xffffff8000000000 - 0xffffff8008000000   (   128 MB)
// [    0.000000]     vmalloc : 0xffffff8008000000 - 0xffffffbdbfff0000   (   246 GB)
// [    0.000000]       .init : 0xffffff8009a00000 - 0xffffff8009c00000   (  2048 KB)
// [    0.000000]       .text : 0xffffff8008080000 - 0xffffff8009200000   ( 17920 KB)
// [    0.000000]     .rodata : 0xffffff8009200000 - 0xffffff8009a00000   (  8192 KB)
// [    0.000000]       .data : 0xffffff8009c00000 - 0xffffff8009e15400   (  2133 KB)
// [    0.000000]     vmemmap : 0xffffffbdc0000000 - 0xffffffbfc0000000   (     8 GB maximum)
// [    0.000000]               0xffffffbdc0000000 - 0xffffffbdc3f93000   (    63 MB actual)
// [    0.000000]     fixed   : 0xffffffbffe7fd000 - 0xffffffbffec00000   (  4108 KB)
// [    0.000000]     PCI I/O : 0xffffffbffee00000 - 0xffffffbfffe00000   (    16 MB)
// [    0.000000]     memory  : 0xffffffc000000000 - 0xffffffc0fe4c0000   (  4068 MB)

/*#define DUMP_BEG 0xffffff8009200000
#define DUMP_END 0xffffff8009a00000

#define TESTER 0xffffff8009200080

#define OFFSETOF_SKC_PROT 0x28
#define OFFSETOF_IOCTL 0x20
#define OFFSETOF_GETSOCKOPT 0x70
#define KERNEL_GETSOCKOPT 0xffffff8008e478b8
#define INET6_IOCTL_END 0xffffff8008f5633c

#define INIT_TASK 0xffffff8009c15a40
#define SELINUX_ENABLED 0xffffff8009c54118
#define SELINUX_ENFORCING 0xffffff8009e73c14

#undef HAS_PTRACE
#undef CONFIG_KEYS
#define CONFIG_SECURITY 1*/

// Oculus Quest - 256550.6810.0

#define TESTER 0xffffff8009200080

#define OFFSETOF_SKC_PROT 0x28
#define OFFSETOF_IOCTL 0x20
#define OFFSETOF_GETSOCKOPT 0x70
#define KERNEL_GETSOCKOPT 0xffffff8008e4bd94
#define INET6_IOCTL_END 0xffffff8008f5a818

#define INIT_TASK 0xffffff8009c15a40
#define SELINUX_ENABLED 0xffffff8009c54318
#define SELINUX_ENFORCING 0xffffff8009e73c14

#undef HAS_PTRACE
#undef CONFIG_KEYS
#define CONFIG_SECURITY 1
