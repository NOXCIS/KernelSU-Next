#include <linux/version.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/thread_info.h>
#include <linux/uaccess.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/printk.h>
#include <asm/current.h>
#include <asm/unistd.h>

#include "klog.h" // IWYU pragma: keep
#include "seccomp_cache.h"

/*
 * Kernel 5.15+ has an action_cache bitmap in seccomp_filter that can be
 * patched to allow specific syscall numbers without modifying the BPF program.
 *
 * Kernel 5.4 does NOT have this bitmap - the seccomp_filter struct only has:
 *   refcount_t usage; bool log; seccomp_filter *prev; bpf_prog *prog; ...
 *
 * For 5.4, we disable seccomp entirely for the target task. This is safe
 * because we only do this for the KSU manager and allowed root processes,
 * which need unrestricted syscall access for root operations. The child
 * processes (libksud.so) inherit the disabled seccomp state.
 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)

/* 5.15+ has the action_cache bitmap - use the original approach */

#ifndef SECCOMP_ARCH_NATIVE_NR
#define SECCOMP_ARCH_NATIVE_NR NR_syscalls
#endif

struct action_cache {
	DECLARE_BITMAP(allow_native, SECCOMP_ARCH_NATIVE_NR);
#ifdef SECCOMP_ARCH_COMPAT
	DECLARE_BITMAP(allow_compat, SECCOMP_ARCH_COMPAT_NR);
#endif
};

struct ksu_seccomp_filter {
	refcount_t refs;
	refcount_t users;
	bool log;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	bool wait_killable_recv;
#endif
	struct action_cache cache;
	struct seccomp_filter *prev;
	struct bpf_prog *prog;
	struct notification *notif;
	struct mutex notify_lock;
	wait_queue_head_t wqh;
};

void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr)
{
	struct ksu_seccomp_filter *f = (struct ksu_seccomp_filter *)filter;
	if (!f) return;

	if (nr >= 0 && nr < SECCOMP_ARCH_NATIVE_NR) {
		clear_bit(nr, f->cache.allow_native);
	}
#ifdef SECCOMP_ARCH_COMPAT
	if (nr >= 0 && nr < SECCOMP_ARCH_COMPAT_NR) {
		clear_bit(nr, f->cache.allow_compat);
	}
#endif
}

void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr)
{
	struct ksu_seccomp_filter *f = (struct ksu_seccomp_filter *)filter;
	if (!f) return;

	if (nr >= 0 && nr < SECCOMP_ARCH_NATIVE_NR) {
		set_bit(nr, f->cache.allow_native);
	}
#ifdef SECCOMP_ARCH_COMPAT
	if (nr >= 0 && nr < SECCOMP_ARCH_COMPAT_NR) {
		set_bit(nr, f->cache.allow_compat);
	}
#endif
}

#else /* kernel < 5.15 - no seccomp cache bitmap */

void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr)
{
	/* No-op on 5.4 */
}

void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr)
{
	/*
	 * On kernel 5.4, seccomp_filter has no action_cache bitmap.
	 * We cannot patch individual syscall permissions.
	 *
	 * Instead, disable seccomp entirely for the current task by detaching
	 * the filter and resetting the mode. This is called from spinlock
	 * context (sighand->siglock held), so we can only do atomic operations.
	 *
	 * We intentionally do NOT call put_seccomp_filter() here because:
	 * 1. We're in spinlock+IRQ-disabled context (can't sleep/free memory)
	 * 2. The filter is reference-counted and shared from zygote, which
	 *    holds its own reference - so the filter stays alive regardless
	 * 3. The minor refcount leak (~1 per manager restart) is negligible
	 *    compared to system uptime
	 *
	 * Child processes (e.g., libksud.so) forked from this task will
	 * inherit the disabled seccomp state, allowing them to call reboot()
	 * and other syscalls needed for KSU communication.
	 */
	if (current->seccomp.filter) {
		pr_info("KernelSU: disabling seccomp for task %d (pid %d) to allow syscall %d\n",
			current->pid, task_tgid_nr(current), nr);
		/*
		 * Order matters: clear TIF_SECCOMP first to prevent any other
		 * CPU from entering __secure_computing() for this thread.
		 * Without this, mode=DISABLED hits "default: BUG()" in
		 * __secure_computing()'s switch statement -> kernel panic.
		 */
		clear_thread_flag(TIF_SECCOMP);
		current->seccomp.mode = SECCOMP_MODE_DISABLED;
		current->seccomp.filter = NULL;
	}
}

#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0) */
