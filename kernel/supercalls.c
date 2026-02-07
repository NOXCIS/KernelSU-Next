#include <linux/anon_inodes.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/utsname.h> // utsname() and uts_sem
#ifdef CONFIG_KSU_SUSFS
#include <linux/namei.h>
#include <linux/susfs.h>
#endif // #ifdef CONFIG_KSU_SUSFS

#include "supercalls.h"
#include "arch.h"
#include "allowlist.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "ksud.h"
#include "kernel_umount.h"
#include "manager.h"
#include "selinux/selinux.h"
#include "file_wrapper.h"
#ifndef CONFIG_KSU_SUSFS
#include "syscall_hook_manager.h"
#endif // #ifndef CONFIG_KSU_SUSFS

#include "tiny_sulog.c"

// Permission check functions
bool only_manager(void)
{
	return ksu_is_manager();
}

bool only_root(void)
{
	return current_uid().val == 0;
}

bool manager_or_root(void)
{
	return current_uid().val == 0 || ksu_is_manager();
}

bool always_allow(void)
{
	return true; // No permission check
}

bool allowed_for_su(void)
{
    bool is_allowed =
        ksu_is_manager() || ksu_is_allow_uid_for_current(current_uid().val);
    return is_allowed;
}

static int do_grant_root(void __user *arg)
{
	// we already check uid above on allowed_for_su()

    write_sulog('i'); // log ioctl escalation

    pr_info("allow root for: %d\n", current_uid().val);
    escape_with_root_profile();

	return 0;
}

static uint32_t ksuver_override = 0;

static int do_get_info(void __user *arg)
{
    struct ksu_get_info_cmd cmd = { .version = KERNEL_SU_VERSION, .flags = 0 };

#ifdef MODULE
	cmd.flags |= 0x1;
#endif

	if (ksuver_override)
	    cmd.version = ksuver_override;

	if (ksu_is_manager()) {
		cmd.flags |= 0x2;
	}
	cmd.features = KSU_FEATURE_MAX;

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_version: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_report_event(void __user *arg)
{
	struct ksu_report_event_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	switch (cmd.event) {
	case EVENT_POST_FS_DATA: {
		static atomic_t post_fs_data_done = ATOMIC_INIT(0);
		if (!atomic_xchg(&post_fs_data_done, 1)) {
			pr_info("post-fs-data triggered\n");
			on_post_fs_data();
		}
		break;
	}
	case EVENT_BOOT_COMPLETED: {
		static atomic_t boot_complete_done = ATOMIC_INIT(0);
		if (!atomic_xchg(&boot_complete_done, 1)) {
			pr_info("boot_complete triggered\n");
			on_boot_completed();
#ifdef CONFIG_KSU_SUSFS
			susfs_start_sdcard_monitor_fn();
#endif // #ifdef CONFIG_KSU_SUSFS
		}
		break;
	}
	case EVENT_MODULE_MOUNTED: {
		/* M2: Idempotency guard — prevent repeated module_mounted calls */
		static atomic_t module_mounted_done = ATOMIC_INIT(0);
		if (atomic_cmpxchg(&module_mounted_done, 0, 1)) {
			pr_info("module already mounted, ignoring\n");
			break;
		}
		pr_info("module mounted!\n");
		on_module_mounted();
		break;
	}
	default:
		break;
	}

	return 0;
}

static int do_set_sepolicy(void __user *arg)
{
	struct ksu_set_sepolicy_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	return handle_sepolicy(cmd.cmd, (void __user *)cmd.arg);
}

static int do_check_safemode(void __user *arg)
{
	struct ksu_check_safemode_cmd cmd;

	cmd.in_safe_mode = ksu_is_safe_mode();

	if (cmd.in_safe_mode) {
		pr_warn("safemode enabled!\n");
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("check_safemode: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_allow_list(void __user *arg)
{
	struct ksu_get_allow_list_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	bool success = ksu_get_allow_list((int *)cmd.uids, (int *)&cmd.count, true);

	if (!success) {
		return -EFAULT;
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_allow_list: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_deny_list(void __user *arg)
{
	struct ksu_get_allow_list_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

    bool success =
        ksu_get_allow_list((int *)cmd.uids, (int *)&cmd.count, false);

	if (!success) {
		return -EFAULT;
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_deny_list: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_uid_granted_root(void __user *arg)
{
	struct ksu_uid_granted_root_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	cmd.granted = ksu_is_allow_uid_for_current(cmd.uid);

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("uid_granted_root: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_uid_should_umount(void __user *arg)
{
	struct ksu_uid_should_umount_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	cmd.should_umount = ksu_uid_should_umount(cmd.uid);

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("uid_should_umount: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_manager_appid(void __user *arg)
{
	struct ksu_get_manager_appid_cmd cmd;

	cmd.appid = ksu_get_manager_appid();

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_manager_appid: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_app_profile(void __user *arg)
{
	struct ksu_get_app_profile_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("get_app_profile: copy_from_user failed\n");
		return -EFAULT;
	}

	if (!ksu_get_app_profile(&cmd.profile)) {
		return -ENOENT;
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_app_profile: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_set_app_profile(void __user *arg)
{
	struct ksu_set_app_profile_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("set_app_profile: copy_from_user failed\n");
		return -EFAULT;
	}

	if (!ksu_set_app_profile(&cmd.profile, true)) {
		return -EFAULT;
	}

	return 0;
}

static int do_get_feature(void __user *arg)
{
	struct ksu_get_feature_cmd cmd;
	bool supported;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("get_feature: copy_from_user failed\n");
		return -EFAULT;
	}


	ret = ksu_get_feature(cmd.feature_id, &cmd.value, &supported);
	cmd.supported = supported ? 1 : 0;

	if (ret && supported) {
		pr_err("get_feature: failed for feature %u: %d\n", cmd.feature_id, ret);
		return ret;
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_feature: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_set_feature(void __user *arg)
{
	struct ksu_set_feature_cmd cmd;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("set_feature: copy_from_user failed\n");
		return -EFAULT;
	}


	ret = ksu_set_feature(cmd.feature_id, cmd.value);
	if (ret) {
		pr_err("set_feature: failed for feature %u: %d\n", cmd.feature_id, ret);
		return ret;
	}

	return 0;
}

static int do_get_wrapper_fd(void __user *arg)
{
    if (!READ_ONCE(ksu_file_sid)) {
        return -EINVAL;
    }

    struct ksu_get_wrapper_fd_cmd cmd;
    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        pr_err("get_wrapper_fd: copy_from_user failed\n");
        return -EFAULT;
    }

    return ksu_install_file_wrapper(cmd.fd);
}

static int do_manage_mark(void __user *arg)
{
	struct ksu_manage_mark_cmd cmd;
	int ret = 0;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("manage_mark: copy_from_user failed\n");
		return -EFAULT;
	}

	switch (cmd.operation) {
	case KSU_MARK_GET: {
#ifndef CONFIG_KSU_SUSFS
		// Get task mark status
		ret = ksu_get_task_mark(cmd.pid);
		if (ret < 0) {
			pr_err("manage_mark: get failed for pid %d: %d\n", cmd.pid, ret);
			return ret;
		}
		cmd.result = (u32)ret;
		break;
#else
	if (susfs_is_current_proc_umounted()) {
		ret = 0; // SYSCALL_TRACEPOINT is NOT flagged
	} else {
		ret = 1; // SYSCALL_TRACEPOINT is flagged
	}
	pr_info("manage_mark: ret for pid %d: %d\n", cmd.pid, ret);
	cmd.result = (u32)ret;
	break;
#endif // #ifndef CONFIG_KSU_SUSFS
	}
	case KSU_MARK_MARK: {
#ifndef CONFIG_KSU_SUSFS
		if (cmd.pid == 0) {
			ksu_mark_all_process();
		} else {
			ret = ksu_set_task_mark(cmd.pid, true);
			if (ret < 0) {
				pr_err("manage_mark: set_mark failed for pid %d: %d\n", cmd.pid,
					ret);
				return ret;
			}
		}
#else
		if (cmd.pid != 0) {
			return -EOPNOTSUPP;
		}
#endif // #ifndef CONFIG_KSU_SUSFS
		break;
	}
	case KSU_MARK_UNMARK: {
#ifndef CONFIG_KSU_SUSFS
		if (cmd.pid == 0) {
			ksu_unmark_all_process();
		} else {
			ret = ksu_set_task_mark(cmd.pid, false);
			if (ret < 0) {
				pr_err("manage_mark: set_unmark failed for pid %d: %d\n",
					cmd.pid, ret);
				return ret;
			}
		}
#else
		if (cmd.pid != 0) {
			return -EOPNOTSUPP;
		}
#endif // #ifndef CONFIG_KSU_SUSFS
		break;
	}
	case KSU_MARK_REFRESH: {
#ifndef CONFIG_KSU_SUSFS
		ksu_mark_running_process();
		pr_info("manage_mark: refreshed running processes\n");
#else
		pr_info("susfs: cmd: KSU_MARK_REFRESH: do nothing\n");
#endif // #ifndef CONFIG_KSU_SUSFS
		break;
	}
	default: {
		pr_err("manage_mark: invalid operation %u\n", cmd.operation);
		return -EINVAL;
	}
	}
	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("manage_mark: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_hook_mode(void __user *arg)
{
	struct ksu_get_hook_mode_cmd cmd = {0};

#ifdef CONFIG_KSU_SUSFS
	strscpy(cmd.mode, "SUSFS", sizeof(cmd.mode));
#else
	strscpy(cmd.mode, "Kprobes", sizeof(cmd.mode));
#endif

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_hook_mode: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_version_tag(void __user *arg)
{
	struct ksu_get_version_tag_cmd cmd = {0};

	strscpy(cmd.tag, KERNEL_SU_VERSION_TAG, sizeof(cmd.tag));

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_version_tag: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_nuke_ext4_sysfs(void __user *arg)
{
    struct ksu_nuke_ext4_sysfs_cmd cmd;
    char mnt[256];
    long ret;

    if (copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;

    if (!cmd.arg)
        return -EINVAL;

    memset(mnt, 0, sizeof(mnt));

    ret = strncpy_from_user(mnt, cmd.arg, sizeof(mnt));
    if (ret < 0) {
        pr_err("nuke ext4 copy mnt failed: %ld\n", ret);
        return ret;
    }

    if (ret == sizeof(mnt)) {
        pr_err("nuke ext4 mnt path too long\n");
        return -ENAMETOOLONG;
    }

    pr_info("do_nuke_ext4_sysfs: %s\n", mnt);

    return nuke_ext4_sysfs(mnt);
}

struct list_head mount_list = LIST_HEAD_INIT(mount_list);
DECLARE_RWSEM(mount_list_lock);

static int add_try_umount(void __user *arg)
{
    struct mount_entry *new_entry, *entry, *tmp;
    struct ksu_add_try_umount_cmd cmd;
    char buf[256] = { 0 };

    if (copy_from_user(&cmd, arg, sizeof cmd))
        return -EFAULT;

    switch (cmd.mode) {
    case KSU_UMOUNT_WIPE: {
        struct mount_entry *entry, *tmp;
        down_write(&mount_list_lock);
        list_for_each_entry_safe (entry, tmp, &mount_list, list) {
            pr_info("wipe_umount_list: removing entry: %s\n",
                    entry->umountable);
            list_del(&entry->list);
            kfree(entry->umountable);
            kfree(entry);
        }
        up_write(&mount_list_lock);

        return 0;
    }

    case KSU_UMOUNT_ADD: {
        long len = strncpy_from_user(buf, (const char __user *)cmd.arg, 256);
        if (len <= 0)
            return -EFAULT;

        buf[sizeof(buf) - 1] = '\0';

        new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);
        if (!new_entry)
            return -ENOMEM;

        new_entry->umountable = kstrdup(buf, GFP_KERNEL);
        if (!new_entry->umountable) {
            kfree(new_entry);
            return -ENOMEM;
        }

        down_write(&mount_list_lock);

        // disallow dupes
        // if this gets too many, we can consider moving this whole task to a kthread
        list_for_each_entry (entry, &mount_list, list) {
            if (!strcmp(entry->umountable, buf)) {
                pr_info("cmd_add_try_umount: %s is already here!\n", buf);
                up_write(&mount_list_lock);
                kfree(new_entry->umountable);
                kfree(new_entry);
                return -EEXIST;
            }
        }

        // now check flags and add
        // this also serves as a null check
        if (cmd.flags)
            new_entry->flags = cmd.flags;
        else
            new_entry->flags = 0;

        // debug
        list_add(&new_entry->list, &mount_list);
        up_write(&mount_list_lock);
        pr_info("cmd_add_try_umount: %s added!\n", buf);

        return 0;
    }

    // this is just strcmp'd wipe anyway
    case KSU_UMOUNT_DEL: {
        long len = strncpy_from_user(buf, (const char __user *)cmd.arg,
                                     sizeof(buf) - 1);
        if (len <= 0)
            return -EFAULT;

        buf[sizeof(buf) - 1] = '\0';

        down_write(&mount_list_lock);
        list_for_each_entry_safe (entry, tmp, &mount_list, list) {
            if (!strcmp(entry->umountable, buf)) {
                pr_info("cmd_add_try_umount: entry removed: %s\n",
                        entry->umountable);
                list_del(&entry->list);
                kfree(entry->umountable);
                kfree(entry);
            }
        }
        up_write(&mount_list_lock);

        return 0;
    }

    // this way userspace can deduce the memory it has to prepare.
    case KSU_UMOUNT_GETSIZE: {
        // check for pointer first
        if (!cmd.arg)
            return -EFAULT;
        
        size_t total_size = 0; // size of list in bytes

        down_read(&mount_list_lock);
        list_for_each_entry(entry, &mount_list, list) {
            total_size = total_size + strlen(entry->umountable) + 1; // + 1 for \0
        }
        up_read(&mount_list_lock);

        // debug
        // pr_info("cmd_add_try_umount: total_size: %zu\n", total_size);
            
        if (copy_to_user((size_t __user *)cmd.arg, &total_size, sizeof(total_size)))
            return -EFAULT;

        return 0;
    }
        
    // WARNING! this is straight up pointerwalking.
    // this way we dont need to redefine the ioctl defs.
    // this also avoids us needing to kmalloc
    // userspace have to send pointer to memory (malloc/alloca) or pointer to a VLA.
    case KSU_UMOUNT_GETLIST: {
        // check for pointer first
        if (!cmd.arg)
            return -EFAULT;

        char *user_buf = (char *)cmd.arg;
        size_t bytes_written = 0;
        /*
         * Cap total output to prevent runaway writes if the list
         * grew between GETSIZE and GETLIST (TOCTOU).  64 KiB is
         * generous for a mount-path list.
         */
        const size_t max_buf = 65536;

        down_read(&mount_list_lock);
        list_for_each_entry(entry, &mount_list, list) {
            size_t entry_len = strlen(entry->umountable) + 1;

            if (bytes_written + entry_len > max_buf) {
                up_read(&mount_list_lock);
                pr_err("cmd_add_try_umount: list exceeds %zu byte cap\n",
                       max_buf);
                return -ENOSPC;
            }

            if (copy_to_user((char __user *)user_buf, entry->umountable, entry_len)) {
                up_read(&mount_list_lock);
                return -EFAULT;
            }

            user_buf += entry_len;
            bytes_written += entry_len;
        }
        up_read(&mount_list_lock);

        return 0;
    }

    default: {
        pr_err("cmd_add_try_umount: invalid operation %u\n", cmd.mode);
        return -EINVAL;
    }

    } // switch(cmd.mode)

    return 0;
}

// IOCTL handlers mapping table
static const struct ksu_ioctl_cmd_map ksu_ioctl_handlers[] = {
    { .cmd = KSU_IOCTL_GRANT_ROOT,
      .name = "GRANT_ROOT",
      .handler = do_grant_root,
      .perm_check = allowed_for_su },
    { .cmd = KSU_IOCTL_GET_INFO,
      .name = "GET_INFO",
      .handler = do_get_info,
      .perm_check = always_allow },
    { .cmd = KSU_IOCTL_REPORT_EVENT,
      .name = "REPORT_EVENT",
      .handler = do_report_event,
      .perm_check = only_root },
    { .cmd = KSU_IOCTL_SET_SEPOLICY,
      .name = "SET_SEPOLICY",
      .handler = do_set_sepolicy,
      .perm_check = only_root },
    { .cmd = KSU_IOCTL_CHECK_SAFEMODE,
      .name = "CHECK_SAFEMODE",
      .handler = do_check_safemode,
      .perm_check = always_allow },
    { .cmd = KSU_IOCTL_GET_ALLOW_LIST,
      .name = "GET_ALLOW_LIST",
      .handler = do_get_allow_list,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_GET_DENY_LIST,
      .name = "GET_DENY_LIST",
      .handler = do_get_deny_list,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_UID_GRANTED_ROOT,
      .name = "UID_GRANTED_ROOT",
      .handler = do_uid_granted_root,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_UID_SHOULD_UMOUNT,
      .name = "UID_SHOULD_UMOUNT",
      .handler = do_uid_should_umount,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_GET_MANAGER_APPID,
      .name = "GET_MANAGER_APPID",
      .handler = do_get_manager_appid,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_GET_APP_PROFILE,
      .name = "GET_APP_PROFILE",
      .handler = do_get_app_profile,
      .perm_check = only_manager },
    { .cmd = KSU_IOCTL_SET_APP_PROFILE,
      .name = "SET_APP_PROFILE",
      .handler = do_set_app_profile,
      .perm_check = only_manager },
    { .cmd = KSU_IOCTL_GET_FEATURE,
      .name = "GET_FEATURE",
      .handler = do_get_feature,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_SET_FEATURE,
      .name = "SET_FEATURE",
      .handler = do_set_feature,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_GET_WRAPPER_FD,
      .name = "GET_WRAPPER_FD",
      .handler = do_get_wrapper_fd,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_MANAGE_MARK,
      .name = "MANAGE_MARK",
      .handler = do_manage_mark,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_NUKE_EXT4_SYSFS,
      .name = "NUKE_EXT4_SYSFS",
      .handler = do_nuke_ext4_sysfs,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_ADD_TRY_UMOUNT,
      .name = "ADD_TRY_UMOUNT",
      .handler = add_try_umount,
      .perm_check = manager_or_root },
	{ .cmd = KSU_IOCTL_GET_HOOK_MODE,
	  .name = "GET_HOOK_MODE",
	  .handler = do_get_hook_mode,
	  .perm_check = manager_or_root },
	{ .cmd = KSU_IOCTL_GET_VERSION_TAG,
	  .name = "GET_VERSION_TAG",
	  .handler = do_get_version_tag,
	  .perm_check = manager_or_root },
    { .cmd = 0, .name = NULL, .handler = NULL, .perm_check = NULL } // Sentinel
};

struct ksu_install_fd_tw {
	struct callback_head cb;
	int __user *outp;
};

static void ksu_install_fd_tw_func(struct callback_head *cb)
{
    struct ksu_install_fd_tw *tw =
        container_of(cb, struct ksu_install_fd_tw, cb);
    int fd = ksu_install_fd();
    pr_info("[%d] install ksu fd: %d\n", current->pid, fd);

	if (copy_to_user(tw->outp, &fd, sizeof(fd))) {
		pr_err("install ksu fd reply err\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
		close_fd(fd);
#else
		ksys_close(fd);
#endif
	}

	kfree(tw);
}

#ifndef CONFIG_KSU_SUSFS
static int reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	int magic1 = (int)PT_REGS_PARM1(real_regs);
	int magic2 = (int)PT_REGS_PARM2(real_regs);
	unsigned int cmd = (unsigned int)PT_REGS_PARM3(real_regs);
	unsigned long arg4 = (unsigned long)PT_REGS_SYSCALL_PARM4(real_regs);
	unsigned long reply = (unsigned long)arg4;

	/* Check if this is a request to install KSU fd */
	if (magic1 == KSU_INSTALL_MAGIC1 && magic2 == KSU_INSTALL_MAGIC2) {
		struct ksu_install_fd_tw *tw;

		tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
		if (!tw)
			return 0;

		tw->outp = (int __user *)arg4;
		tw->cb.func = ksu_install_fd_tw_func;

		if (task_work_add(current, &tw->cb, TWA_RESUME)) {
			kfree(tw);
			pr_warn("install fd add task_work failed\n");
		}
	}

	if (magic2 == CHANGE_MANAGER_UID) {
		/* only root is allowed for this command */
		if (current_uid().val != 0)
			return 0;

		pr_info("sys_reboot: ksu_set_manager_appid to: %d\n", cmd);
		ksu_set_manager_appid(cmd);

		if (cmd == ksu_get_manager_appid()) {
			if (copy_to_user((void __user *)arg4, &reply, sizeof(reply)))
				pr_info("sys_reboot: reply fail\n");
		}

		return 0;
	}

	if (magic2 == GET_SULOG_DUMP_V2) {
		if (current_uid().val != 0)
			return 0;

		int ret = send_sulog_dump((void __user *)arg4);
            if (ret)
                return 0;

        if (copy_to_user((void __user *)arg4, &reply, sizeof(reply) ))
            return 0;
	}

    if (magic2 == CHANGE_KSUVER) {
        if (current_uid().val != 0)
            return 0;

        pr_info("sys_reboot: ksu_change_ksuver to: %d\n", cmd);
        ksuver_override = cmd;

        if (copy_to_user((void __user *)arg4, &reply, sizeof(reply) ))
            return 0;
    }

	// WARNING!!! triple ptr zone! ***
	// https://wiki.c2.com/?ThreeStarProgrammer
	if (magic2 == CHANGE_SPOOF_UNAME) {
		// only root is allowed for this command 
		if (current_uid().val != 0)
			return 0;

		char release_buf[65];
		char version_buf[65];
		static char original_release_buf[65] = {0};
		static char original_version_buf[65] = {0};

		// basically void * void __user * void __user *arg
		void __user **ppptr = (void __user **)arg4;

		// user pointer storage
		// init this as zero so this works on 32-on-64 compat (LE)
		uint64_t u_pptr = 0;
		uint64_t u_ptr = 0;

		pr_info("sys_reboot: reading uname spoof data\n");

		// arg here is ***, pull out user-space ** via copy_from_user
		if (copy_from_user(&u_pptr, ppptr, sizeof(u_pptr)))
			return 0;

		pr_info("sys_reboot: read user pointer level 1\n");

		// now we got the __user **
		// we cannot dereference this as this is __user
		// we just do another copy_from_user to get it
		if (copy_from_user(&u_ptr, (void __user *)u_pptr, sizeof(u_ptr)))
			return 0;

		pr_info("sys_reboot: read user pointer level 2\n");

		// for release
		if (strncpy_from_user(release_buf, (char __user *)u_ptr, sizeof(release_buf)) < 0)
			return 0;
		release_buf[sizeof(release_buf) - 1] = '\0'; 

		// for version
		if (strncpy_from_user(version_buf, (char __user *)(u_ptr + strlen(release_buf) + 1), sizeof(version_buf)) < 0)
			return 0;
		version_buf[sizeof(version_buf) - 1] = '\0'; 

		/* M6: Use atomic flag to prevent race on original_*_buf save */
		{
			static atomic_t original_saved = ATOMIC_INIT(0);
			if (!atomic_cmpxchg(&original_saved, 0, 1)) {
				struct new_utsname *u_curr;
				down_read(&uts_sem);
				u_curr = utsname();
				/* M4: strscpy always NUL-terminates */
				strscpy(original_release_buf, u_curr->release, sizeof(original_release_buf));
				strscpy(original_version_buf, u_curr->version, sizeof(original_version_buf));
				up_read(&uts_sem);
				pr_info("sys_reboot: original uname saved: %s %s\n", original_release_buf, original_version_buf);
			}
		}

		// so user can reset
		if (!strcmp(release_buf, "default") || !strcmp(version_buf, "default") ) {
			memcpy(release_buf, original_release_buf, sizeof(release_buf));
			memcpy(version_buf, original_version_buf, sizeof(version_buf));
		}

		pr_info("sys_reboot: spoofing kernel to: %s - %s\n", release_buf, version_buf);

		struct new_utsname *u = utsname();

		down_write(&uts_sem);
		/* M4: strscpy always NUL-terminates */
		strscpy(u->release, release_buf, sizeof(u->release));
		strscpy(u->version, version_buf, sizeof(u->version));
		up_write(&uts_sem);

		// we write our confirmation on **
		if (copy_to_user((void __user *)arg4, &reply, sizeof(reply)))
			return 0;
	}

	return 0;
}

static struct kprobe reboot_kp = {
	.symbol_name = REBOOT_SYMBOL,
	.pre_handler = reboot_handler_pre,
};
#else
int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg)
{
	unsigned long arg4 = (unsigned long)(*arg);
	unsigned long reply = arg4;

	if (magic1 != KSU_INSTALL_MAGIC1) {
		return -EINVAL;
	}

	// Check if this is a request to install KSU fd
	if (magic2 == KSU_INSTALL_MAGIC2) {
		struct ksu_install_fd_tw *tw;

		tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
		if (!tw)
			return 0;

		tw->outp = (int __user *)(*arg);
		tw->cb.func = ksu_install_fd_tw_func;

		if (task_work_add(current, &tw->cb, TWA_RESUME)) {
			kfree(tw);
			pr_warn("install fd add task_work failed\n");
		}
		return 0;
	}

	// Toolkit: set manager app ID (root only)
	if (magic2 == CHANGE_MANAGER_UID) {
		if (current_uid().val != 0)
			return 0;

		pr_info("sys_reboot: ksu_set_manager_appid to: %d\n", cmd);
		ksu_set_manager_appid(cmd);

		if (cmd == ksu_get_manager_appid()) {
			if (copy_to_user((void __user *)arg4, &reply, sizeof(reply)))
				pr_info("sys_reboot: reply fail\n");
		}
		return 0;
	}

	// Toolkit: get su log dump (root only)
	if (magic2 == GET_SULOG_DUMP_V2) {
		if (current_uid().val != 0)
			return 0;

		int ret = send_sulog_dump((void __user *)arg4);
		if (ret)
			return 0;

		if (copy_to_user((void __user *)arg4, &reply, sizeof(reply)))
			return 0;

		return 0;
	}

	// Toolkit: override KSU version (root only)
	if (magic2 == CHANGE_KSUVER) {
		if (current_uid().val != 0)
			return 0;

		pr_info("sys_reboot: ksu_change_ksuver to: %d\n", cmd);
		ksuver_override = cmd;

		if (copy_to_user((void __user *)arg4, &reply, sizeof(reply)))
			return 0;

		return 0;
	}

	// Toolkit: spoof uname (root only)
	if (magic2 == CHANGE_SPOOF_UNAME) {
		if (current_uid().val != 0)
			return 0;

		char release_buf[65];
		char version_buf[65];
		static char original_release_buf[65] = {0};
		static char original_version_buf[65] = {0};

		void __user **ppptr = (void __user **)arg4;
		uint64_t u_pptr = 0;
		uint64_t u_ptr = 0;

		if (copy_from_user(&u_pptr, ppptr, sizeof(u_pptr)))
			return 0;
		if (copy_from_user(&u_ptr, (void __user *)u_pptr, sizeof(u_ptr)))
			return 0;

		if (strncpy_from_user(release_buf, (char __user *)u_ptr, sizeof(release_buf)) < 0)
			return 0;
		release_buf[sizeof(release_buf) - 1] = '\0';

		if (strncpy_from_user(version_buf, (char __user *)(u_ptr + strlen(release_buf) + 1), sizeof(version_buf)) < 0)
			return 0;
		version_buf[sizeof(version_buf) - 1] = '\0';

		/* M6: Use atomic flag to prevent race on original_*_buf save */
		{
			static atomic_t original_saved = ATOMIC_INIT(0);
			if (!atomic_cmpxchg(&original_saved, 0, 1)) {
				struct new_utsname *u_curr;
				down_read(&uts_sem);
				u_curr = utsname();
				/* M4: strscpy always NUL-terminates */
				strscpy(original_release_buf, u_curr->release, sizeof(original_release_buf));
				strscpy(original_version_buf, u_curr->version, sizeof(original_version_buf));
				up_read(&uts_sem);
				pr_info("sys_reboot: original uname saved: %s %s\n", original_release_buf, original_version_buf);
			}
		}

		if (!strcmp(release_buf, "default") || !strcmp(version_buf, "default")) {
			memcpy(release_buf, original_release_buf, sizeof(release_buf));
			memcpy(version_buf, original_version_buf, sizeof(version_buf));
		}

		pr_info("sys_reboot: spoofing kernel to: %s - %s\n", release_buf, version_buf);

		struct new_utsname *u = utsname();
		down_write(&uts_sem);
		/* M4: strscpy always NUL-terminates */
		strscpy(u->release, release_buf, sizeof(u->release));
		strscpy(u->version, version_buf, sizeof(u->version));
		up_write(&uts_sem);

		if (copy_to_user((void __user *)arg4, &reply, sizeof(reply)))
			return 0;

		return 0;
	}

	/*
	 * SUSFS v2.0.0 command dispatch via reboot() supercall.
	 *
	 * The v2.0.0 ksu_susfs binary passes a struct pointer as the 4th arg
	 * to reboot(). Each struct has 'int err' as its LAST field, initialized
	 * to 255 (ERR_CMD_NOT_SUPPORTED). The kernel must set err=0 on success.
	 *
	 * The helper macro SUSFS_SET_ERR writes err=0 at a known byte offset
	 * from the start of the user struct.
	 */
#define SUSFS_SET_ERR(uptr, offset) \
	do { int __zero = 0; put_user(__zero, (int __user *)((char __user *)(uptr) + (offset))); } while (0)

	/* v2.0.0 struct err field offsets (ARM64) */
	/* st_susfs_sus_path:     {ulong(8)+char[256]+uint(4)+int err(4)} → offset 268 */
	/* st_external_dir:       {char[256]+bool(1)+pad(3)+int cmd(4)+int err(4)} → offset 264 */
	/* st_susfs_sus_mount:    {char[256]+ulong(8)+int err(4)} → offset 264 */
	/* st_susfs_hide_*:       {bool(1)+pad(3)+int err(4)} → offset 4 */
	/* st_susfs_sus_kstat:    {bool(1)+pad(7)+ulong(8)+char[256]+ulong(8)+ulong(8)+uint(4)+pad(4)+ll(8)+6*long(48)+ulong(8)+ull(8)+int err(4)} → offset 368 */
	/* st_susfs_try_umount:   {char[256]+int(4)+int err(4)} → offset 260 */
	/* st_susfs_uname:        {char[65]+char[65]+pad(2)+int err(4)} → offset 132 */
	/* st_susfs_log:          {bool(1)+pad(3)+int err(4)} → offset 4 */
	/* st_susfs_cmdline:      {char[8192]+int err(4)} → offset 8192 */
	/* st_susfs_open_redirect:{ulong(8)+char[256]+char[256]+int err(4)} → offset 520 */
	/* st_susfs_sus_map:      {char[256]+int err(4)} → offset 256 */
	/* st_susfs_avc_log:      {bool(1)+pad(3)+int err(4)} → offset 4 */
	if (magic2 == SUSFS_MAGIC && current_uid().val == 0) {
		void __user *uptr = (void __user *)(*arg);
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
		if (cmd == CMD_SUSFS_ADD_SUS_PATH) {
			susfs_add_sus_path((struct st_susfs_sus_path __user *)uptr);
			SUSFS_SET_ERR(uptr, 268);
			return 0;
		}
		if (cmd == CMD_SUSFS_ADD_SUS_PATH_LOOP) {
			susfs_add_sus_path_loop(arg);
			SUSFS_SET_ERR(uptr, 268);
			return 0;
		}
		if (cmd == CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH ||
		    cmd == CMD_SUSFS_SET_SDCARD_ROOT_PATH) {
			susfs_set_i_state_on_external_dir(arg);
			SUSFS_SET_ERR(uptr, 264);
			return 0;
		}
#endif //#ifdef CONFIG_KSU_SUSFS_SUS_PATH
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
		if (cmd == CMD_SUSFS_ADD_SUS_MOUNT) {
			susfs_add_sus_mount((struct st_susfs_sus_mount __user *)uptr);
			SUSFS_SET_ERR(uptr, 264);
			return 0;
		}
		if (cmd == CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS) {
			susfs_set_hide_sus_mnts_for_non_su_procs(arg);
			SUSFS_SET_ERR(uptr, 4);
			return 0;
		}
#endif //#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
		if (cmd == CMD_SUSFS_ADD_SUS_KSTAT ||
		    cmd == CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY) {
			susfs_add_sus_kstat((struct st_susfs_sus_kstat __user *)uptr);
			SUSFS_SET_ERR(uptr, 368);
			return 0;
		}
		if (cmd == CMD_SUSFS_UPDATE_SUS_KSTAT) {
			susfs_update_sus_kstat((struct st_susfs_sus_kstat __user *)uptr);
			SUSFS_SET_ERR(uptr, 368);
			return 0;
		}
#endif //#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
		if (cmd == CMD_SUSFS_ADD_TRY_UMOUNT) {
			susfs_add_try_umount((struct st_susfs_try_umount __user *)uptr);
			SUSFS_SET_ERR(uptr, 260);
			return 0;
		}
#endif //#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
		if (cmd == CMD_SUSFS_SET_UNAME) {
			susfs_set_uname((struct st_susfs_uname __user *)uptr);
			SUSFS_SET_ERR(uptr, 132);
			return 0;
		}
#endif //#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
		if (cmd == CMD_SUSFS_ENABLE_LOG) {
			susfs_enable_log(arg);
			SUSFS_SET_ERR(uptr, 4);
			return 0;
		}
#endif //#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
		if (cmd == CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG) {
			susfs_set_cmdline_or_bootconfig((char __user *)uptr);
			SUSFS_SET_ERR(uptr, 8192);
			return 0;
		}
#endif //#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
		if (cmd == CMD_SUSFS_ADD_OPEN_REDIRECT) {
			susfs_add_open_redirect((struct st_susfs_open_redirect __user *)uptr);
			SUSFS_SET_ERR(uptr, 520);
			return 0;
		}
#endif //#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
		if (cmd == CMD_SUSFS_ADD_SUS_MAP) {
			susfs_add_sus_map(arg);
			SUSFS_SET_ERR(uptr, 256);
			return 0;
		}
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MAP
		if (cmd == CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING) {
			susfs_set_avc_log_spoofing(arg);
			SUSFS_SET_ERR(uptr, 4);
			return 0;
		}
		/* show commands - handled directly by susfs_* functions which
		 * write data + err into the v2.0.0 struct themselves */
		if (cmd == CMD_SUSFS_SHOW_ENABLED_FEATURES) {
			susfs_get_enabled_features(arg);
			return 0;
		}
		if (cmd == CMD_SUSFS_SHOW_VARIANT) {
			susfs_show_variant(arg);
			return 0;
		}
		if (cmd == CMD_SUSFS_SHOW_VERSION) {
			susfs_show_version(arg);
			return 0;
		}
		return 0;
	}
#undef SUSFS_SET_ERR

	return 0;
}

/*
 * Handle SUSFS commands via prctl() for compatibility with the ksu_susfs
 * userspace tool (v1.5.x) which uses prctl(0xDEADBEEF, CMD, ...) instead
 * of the reboot() supercall interface used by the dev_susfs branch.
 *
 * prctl signature: prctl(option, arg2, arg3, arg4, arg5)
 *   option = 0xDEADBEEF (KERNEL_SU_OPTION)
 *   arg2   = CMD_SUSFS_* command
 *   arg3   = data pointer (input/output buffer)
 *   arg4   = unused (typically NULL)
 *   arg5   = error return pointer
 */
int ksu_handle_prctl_susfs(int option, unsigned long arg2, unsigned long arg3,
			   unsigned long arg4, unsigned long arg5)
{
	int error = 0;

	/* Only root can use SUSFS commands */
	if (current_uid().val != 0) {
		return -EACCES;
	}

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	if (arg2 == CMD_SUSFS_ADD_SUS_PATH) {
		error = susfs_add_sus_path((struct st_susfs_sus_path __user *)arg3);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_err("susfs: CMD_SUSFS_ADD_SUS_PATH -> copy_to_user failed\n");
		return 0;
	}
	if (arg2 == CMD_SUSFS_ADD_SUS_PATH_LOOP) {
		void __user *uptr = (void __user *)arg3;
		susfs_add_sus_path_loop(&uptr);
		error = 0;
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_err("susfs: copy_to_user failed\n");
		return 0;
	}
	if (arg2 == CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH ||
	    arg2 == CMD_SUSFS_SET_SDCARD_ROOT_PATH) {
		void __user *uptr = (void __user *)arg3;
		susfs_set_i_state_on_external_dir(&uptr);
		error = 0;
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_err("susfs: copy_to_user failed\n");
		return 0;
	}
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	if (arg2 == CMD_SUSFS_ADD_SUS_MOUNT) {
		error = susfs_add_sus_mount((struct st_susfs_sus_mount __user *)arg3);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_err("susfs: copy_to_user failed\n");
		return 0;
	}
	if (arg2 == CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS) {
		void __user *uptr = (void __user *)arg3;
		susfs_set_hide_sus_mnts_for_non_su_procs(&uptr);
		error = 0;
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_err("susfs: copy_to_user failed\n");
		return 0;
	}
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
	if (arg2 == CMD_SUSFS_ADD_SUS_KSTAT) {
		error = susfs_add_sus_kstat((struct st_susfs_sus_kstat __user *)arg3);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_err("susfs: copy_to_user failed\n");
		return 0;
	}
	if (arg2 == CMD_SUSFS_UPDATE_SUS_KSTAT) {
		error = susfs_update_sus_kstat((struct st_susfs_sus_kstat __user *)arg3);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_err("susfs: copy_to_user failed\n");
		return 0;
	}
	if (arg2 == CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY) {
		error = susfs_add_sus_kstat((struct st_susfs_sus_kstat __user *)arg3);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_err("susfs: copy_to_user failed\n");
		return 0;
	}
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
	if (arg2 == CMD_SUSFS_ADD_TRY_UMOUNT) {
		error = susfs_add_try_umount((struct st_susfs_try_umount __user *)arg3);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_err("susfs: copy_to_user failed\n");
		return 0;
	}
	if (arg2 == CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS) {
		/* no-op in v1.5.5 stub */
		error = 0;
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_err("susfs: copy_to_user failed\n");
		return 0;
	}
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
	if (arg2 == CMD_SUSFS_SET_UNAME) {
		error = susfs_set_uname((struct st_susfs_uname __user *)arg3);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_err("susfs: copy_to_user failed\n");
		return 0;
	}
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
	if (arg2 == CMD_SUSFS_ENABLE_LOG) {
		susfs_set_log(arg3 ? true : false);
		error = 0;
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_err("susfs: copy_to_user failed\n");
		return 0;
	}
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
	if (arg2 == CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG) {
		error = susfs_set_cmdline_or_bootconfig((char __user *)arg3);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_err("susfs: copy_to_user failed\n");
		return 0;
	}
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
	if (arg2 == CMD_SUSFS_ADD_OPEN_REDIRECT) {
		error = susfs_add_open_redirect((struct st_susfs_open_redirect __user *)arg3);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_err("susfs: copy_to_user failed\n");
		return 0;
	}
#endif
	if (arg2 == CMD_SUSFS_SHOW_VERSION) {
		const char *version = SUSFS_VERSION;
		error = copy_to_user((void __user *)arg3, version, strlen(version) + 1);
		pr_info("susfs: CMD_SUSFS_SHOW_VERSION -> %s, ret: %d\n", version, error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_err("susfs: copy_to_user failed\n");
		return 0;
	}
	if (arg2 == CMD_SUSFS_SHOW_ENABLED_FEATURES) {
		u64 enabled_features = 0;
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
		enabled_features |= (1 << 0);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
		enabled_features |= (1 << 1);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
		enabled_features |= (1 << 2);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
		enabled_features |= (1 << 3);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
		enabled_features |= (1 << 4);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_OVERLAYFS
		enabled_features |= (1 << 5);
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
		enabled_features |= (1 << 6);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
		enabled_features |= (1 << 7);
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
		enabled_features |= (1 << 8);
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
		enabled_features |= (1 << 9);
#endif
#ifdef CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS
		enabled_features |= (1 << 10);
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
		enabled_features |= (1 << 11);
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
		enabled_features |= (1 << 12);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_SU
		enabled_features |= (1 << 13);
#endif
#ifdef CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT
		enabled_features |= (1 << 14);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
		enabled_features |= (1 << 15);
#endif
		error = copy_to_user((void __user *)arg3, &enabled_features, sizeof(enabled_features));
		pr_info("susfs: CMD_SUSFS_SHOW_ENABLED_FEATURES -> 0x%llx, ret: %d\n", enabled_features, error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_err("susfs: copy_to_user failed\n");
		return 0;
	}
	if (arg2 == CMD_SUSFS_SHOW_VARIANT) {
		const char *variant = SUSFS_VARIANT;
		error = copy_to_user((void __user *)arg3, variant, strlen(variant) + 1);
		pr_info("susfs: CMD_SUSFS_SHOW_VARIANT -> %s, ret: %d\n", variant, error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_err("susfs: copy_to_user failed\n");
		return 0;
	}
#ifdef CONFIG_KSU_SUSFS_SUS_SU
	if (arg2 == CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE) {
		int mode = susfs_get_sus_su_working_mode();
		error = copy_to_user((void __user *)arg3, &mode, sizeof(mode));
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_err("susfs: copy_to_user failed\n");
		return 0;
	}
	if (arg2 == CMD_SUSFS_IS_SUS_SU_READY) {
		/* Not implemented - return not ready */
		bool ready = false;
		error = copy_to_user((void __user *)arg3, &ready, sizeof(ready));
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_err("susfs: copy_to_user failed\n");
		return 0;
	}
	if (arg2 == CMD_SUSFS_SUS_SU) {
		error = susfs_sus_su((struct st_sus_su __user *)arg3);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_err("susfs: copy_to_user failed\n");
		return 0;
	}
#endif
	/* Unknown SUSFS command - return 0 but set error to -1 */
	error = -1;
	if (arg5)
		copy_to_user((void __user *)arg5, &error, sizeof(error));
	return 0;
}
#endif // #ifndef CONFIG_KSU_SUSFS

void ksu_supercalls_init(void)
{
	int i;

    pr_info("KernelSU IOCTL Commands:\n");
    for (i = 0; ksu_ioctl_handlers[i].handler; i++) {
        pr_info("  %-18s = 0x%08x\n", ksu_ioctl_handlers[i].name,
                ksu_ioctl_handlers[i].cmd);
    }

#ifndef CONFIG_KSU_SUSFS
	int rc = register_kprobe(&reboot_kp);
	if (rc) {
		pr_err("reboot kprobe failed: %d\n", rc);
	} else {
		pr_info("reboot kprobe registered successfully\n");
	}
#endif // #ifndef CONFIG_KSU_SUSFS

    sulog_init_heap(); // grab heap memory
}

void ksu_supercalls_exit(void)
{
#ifndef CONFIG_KSU_SUSFS
    unregister_kprobe(&reboot_kp);
#else
    pr_info("susfs: do nothing\n");
#endif // #ifndef CONFIG_KSU_SUSFS
}

// IOCTL dispatcher
static long anon_ksu_ioctl(struct file *filp, unsigned int cmd,
                           unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	int i;

#ifdef CONFIG_KSU_DEBUG
	pr_info("ksu ioctl: cmd=0x%x from uid=%d\n", cmd, current_uid().val);
#endif

    for (i = 0; ksu_ioctl_handlers[i].handler; i++) {
        if (cmd == ksu_ioctl_handlers[i].cmd) {
            // Check permission first
            if (ksu_ioctl_handlers[i].perm_check &&
                !ksu_ioctl_handlers[i].perm_check()) {
                pr_warn("ksu ioctl: permission denied for cmd=0x%x uid=%d\n",
                        cmd, current_uid().val);
                return -EPERM;
            }
            // Execute handler
            return ksu_ioctl_handlers[i].handler(argp);
        }
    }

	pr_warn("ksu ioctl: unsupported command 0x%x\n", cmd);
	return -ENOTTY;
}

// File release handler
static int anon_ksu_release(struct inode *inode, struct file *filp)
{
	pr_info("ksu fd released\n");
	return 0;
}

// File operations structure
static const struct file_operations anon_ksu_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = anon_ksu_ioctl,
	.compat_ioctl = anon_ksu_ioctl,
	.release = anon_ksu_release,
};

// Install KSU fd to current process
int ksu_install_fd(void)
{
	struct file *filp;
	int fd;

	// Get unused fd
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		pr_err("ksu_install_fd: failed to get unused fd\n");
		return fd;
	}

    // Create anonymous inode file
    filp = anon_inode_getfile("[ksu_driver]", &anon_ksu_fops, NULL,
                              O_RDWR | O_CLOEXEC);
    if (IS_ERR(filp)) {
        pr_err("ksu_install_fd: failed to create anon inode file\n");
        put_unused_fd(fd);
        return PTR_ERR(filp);
    }

	// Install fd
	fd_install(fd, filp);

	pr_info("ksu fd installed: %d for pid %d\n", fd, current->pid);

	return fd;
}
