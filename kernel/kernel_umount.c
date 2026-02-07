#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/types.h>

#include "kernel_umount.h"
#include "klog.h" // IWYU pragma: keep
#include "allowlist.h"
#include "selinux/selinux.h"
#include "feature.h"
#include "ksud.h"
#include "ksu.h"

static bool ksu_kernel_umount_enabled = true;

static int kernel_umount_feature_get(u64 *value)
{
	*value = READ_ONCE(ksu_kernel_umount_enabled) ? 1 : 0;
	return 0;
}

static int kernel_umount_feature_set(u64 value)
{
	bool enable = value != 0;
	WRITE_ONCE(ksu_kernel_umount_enabled, enable);
	pr_info("kernel_umount: set to %d\n", enable);
	return 0;
}

static const struct ksu_feature_handler kernel_umount_handler = {
	.feature_id = KSU_FEATURE_KERNEL_UMOUNT,
	.name = "kernel_umount",
	.get_handler = kernel_umount_feature_get,
	.set_handler = kernel_umount_feature_set,
};

extern int path_umount(struct path *path, int flags);

static void ksu_umount_mnt(struct path *path, int flags)
{
	/* Capture name BEFORE path_umount, which calls dput+mntput and may
	 * free the dentry. d_iname is a fixed inline array so memcpy is safe
	 * as long as the dentry is still alive (which it is here). */
	char name_buf[DNAME_INLINE_LEN];
	int err;

	memcpy(name_buf, path->dentry->d_iname, sizeof(name_buf));
	name_buf[sizeof(name_buf) - 1] = '\0';

	err = path_umount(path, flags);
	if (err) {
		pr_info("umount %s failed: %d\n", name_buf, err);
	}
}

static void try_umount(const char *mnt, int flags)
{
	struct path path;
	int err = kern_path(mnt, 0, &path);
	if (err) {
		return;
	}

	if (path.dentry != path.mnt->mnt_root) {
		// it is not root mountpoint, maybe umounted by others already.
		path_put(&path);
		return;
	}

    ksu_umount_mnt(&path, flags);
    /* NOTE: path_umount() internally calls dput + mntput, so NO path_put here */
}

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
/*
 * Exported version of try_umount for SUSFS.
 * The check_mnt and uid parameters are accepted for API compat but
 * the underlying implementation just does kern_path + umount.
 */
void ksu_try_umount(const char *mnt, bool check_mnt, int flags, uid_t uid)
{
	try_umount(mnt, flags);
}
#endif

struct umount_tw {
	struct callback_head cb;
	const struct cred *cred_ref; /* M13: hold reference to avoid TOCTOU UAF */
};

static void umount_tw_func(struct callback_head *cb)
{
	struct umount_tw *tw = container_of(cb, struct umount_tw, cb);
	const struct cred *saved = override_creds(tw->cred_ref);

    struct mount_entry *entry;
    down_read(&mount_list_lock);
    list_for_each_entry (entry, &mount_list, list) {
        pr_info("%s: unmounting: %s flags 0x%x\n", __func__, entry->umountable,
                entry->flags);
        try_umount(entry->umountable, entry->flags);
    }
    up_read(&mount_list_lock);

	revert_creds(saved);
	put_cred(tw->cred_ref);
	kfree(tw);
}

int ksu_handle_umount(uid_t old_uid, uid_t new_uid)
{
	struct umount_tw *tw;

	// if there isn't any module mounted, just ignore it!
	if (!READ_ONCE(ksu_module_mounted)) {
		return 0;
	}

	if (!READ_ONCE(ksu_kernel_umount_enabled)) {
		return 0;
	}

	if (!ksu_cred) {
		return 0;
	}

#ifndef CONFIG_KSU_SUSFS
    // There are 5 scenarios:
    // 1. Normal app: zygote -> appuid
    // 2. Isolated process forked from zygote: zygote -> isolated_process
    // 3. App zygote forked from zygote: zygote -> appuid
    // 4. Isolated process froked from app zygote: appuid -> isolated_process (already handled by 3)
    // 5. Isolated process froked from webview zygote (no need to handle, app cannot run custom code)
    if (!is_appuid(new_uid) && !is_isolated_process(new_uid)) {
        return 0;
    }

	if (!ksu_uid_should_umount(new_uid) && !is_isolated_process(new_uid)) {
		return 0;
	}

	// check old process's selinux context, if it is not zygote, ignore it!
	// because some su apps may setuid to untrusted_app but they are in global mount namespace
	// when we umount for such process, that is a disaster!
	// also handle case 4 and 5
	bool is_zygote_child = is_zygote(current_cred());
	if (!is_zygote_child) {
		pr_info("handle umount ignore non zygote child: %d\n", current->pid);
		return 0;
	}
#endif // #ifndef CONFIG_KSU_SUSFS

	// umount the target mnt
	pr_info("handle umount for uid: %d, pid: %d\n", new_uid, current->pid);

	tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
	if (!tw)
		return 0;

	/* M13: Take cred reference now to prevent UAF if ksu_cred is freed
	 * between scheduling and task_work execution */
	tw->cred_ref = get_cred(ksu_cred);
	tw->cb.func = umount_tw_func;

	int err = task_work_add(current, &tw->cb, TWA_RESUME);
	if (err) {
		put_cred(tw->cred_ref);
		kfree(tw);
		pr_warn("unmount add task_work failed\n");
	}

	return 0;
}

void ksu_kernel_umount_init(void)
{
	if (ksu_register_feature_handler(&kernel_umount_handler)) {
		pr_err("Failed to register kernel_umount feature handler\n");
	}
}

void ksu_kernel_umount_exit(void)
{
	ksu_unregister_feature_handler(KSU_FEATURE_KERNEL_UMOUNT);
}
