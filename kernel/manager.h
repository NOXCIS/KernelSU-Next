#ifndef __KSU_H_KSU_MANAGER
#define __KSU_H_KSU_MANAGER

#include <linux/cred.h>
#include <linux/types.h>
#include "allowlist.h"

#define KSU_INVALID_APPID -1

extern uid_t ksu_manager_appid; // DO NOT DIRECT USE

/* L4: Use READ_ONCE/WRITE_ONCE for ksu_manager_appid to prevent
 * compiler-induced torn reads/writes and ensure ordering. */
static inline bool ksu_is_manager_appid_valid(void)
{
	return READ_ONCE(ksu_manager_appid) != KSU_INVALID_APPID;
}

static inline bool ksu_is_manager(void)
{
	uid_t uid = current_uid().val;
	uid_t appid = READ_ONCE(ksu_manager_appid);
	return likely(appid != KSU_INVALID_APPID) &&
	       unlikely(uid / PER_USER_RANGE == 0) &&
	       unlikely(appid == uid % PER_USER_RANGE);
}

static inline uid_t ksu_get_manager_appid(void)
{
	return READ_ONCE(ksu_manager_appid);
}

static inline void ksu_set_manager_appid(uid_t appid)
{
	WRITE_ONCE(ksu_manager_appid, appid);
}

static inline void ksu_invalidate_manager_uid(void)
{
	WRITE_ONCE(ksu_manager_appid, KSU_INVALID_APPID);
}

int ksu_observer_init(void);
#endif
