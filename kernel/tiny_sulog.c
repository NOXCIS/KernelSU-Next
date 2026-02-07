// half assed ringbuffer
// 8 bytes
struct sulog_entry {
	uint32_t s_time; // uptime in seconds
	uint32_t data; // uint8_t[0,1,2] = uid, basically uint24_t, uint8_t[3] = symbol
} __attribute__((packed));

#define SULOG_ENTRY_MAX 250
/* L10: Parenthesize macro to prevent precedence issues */
#define SULOG_BUFSIZ (SULOG_ENTRY_MAX * sizeof(struct sulog_entry))

static void *sulog_buf_ptr = NULL;
/* L11: Use unsigned int to avoid silent wrap if SULOG_ENTRY_MAX > 255 */
static unsigned int sulog_index_next = 0;

static DEFINE_SPINLOCK(sulog_lock);

void sulog_init_heap()
{
	sulog_buf_ptr = kzalloc(SULOG_BUFSIZ, GFP_KERNEL);
	if (!sulog_buf_ptr)
		sulog_buf_ptr = NULL;
	
	pr_info("sulog_init: allocated %lu bytes\n", (unsigned long)SULOG_BUFSIZ);
}

void write_sulog(uint8_t sym)
{
	unsigned int offset;
	struct sulog_entry entry = {0};

	if (!sulog_buf_ptr)
		return;

	// WARNING!!! this is LE only!
	entry.s_time = (uint32_t)(ktime_get_boottime() / 1000000000);
	entry.data = (uint32_t)current_uid().val;
	/* M14: Cast to char* for defined pointer arithmetic (void* is UB in ISO C) */
	memcpy((char *)&entry.data + 3, &sym, 1);

	spin_lock(&sulog_lock);
	offset = sulog_index_next * sizeof(struct sulog_entry);
	memcpy((char *)sulog_buf_ptr + offset, &entry, sizeof(entry));
	sulog_index_next = sulog_index_next + 1;
	if (sulog_index_next >= SULOG_ENTRY_MAX)
		sulog_index_next = 0;
	spin_unlock(&sulog_lock);
}

struct sulog_entry_rcv_ptr {
	uint64_t index_ptr; // send index here
	uint64_t buf_ptr; // send buf here
	uint64_t uptime_ptr; // uptime
};

int send_sulog_dump(void __user *uptr)
{
	struct sulog_entry_rcv_ptr sbuf = {0};
	void *tmp_buf;
	unsigned int tmp_index;
	uint32_t uptime;

	if (!sulog_buf_ptr)
		return 1;

	if (copy_from_user(&sbuf, uptr, sizeof(sbuf)))
		return 1;

	if (!sbuf.index_ptr || !sbuf.buf_ptr || !sbuf.uptime_ptr)
		return 1;

	// send uptime
	uptime = (uint32_t)(ktime_get_boottime() / 1000000000);
	if (copy_to_user((void __user *)sbuf.uptime_ptr, &uptime, sizeof(uptime)))
		return 1;

	// snapshot buffer under lock, then copy_to_user outside lock
	tmp_buf = kmalloc(SULOG_BUFSIZ, GFP_KERNEL);
	if (!tmp_buf)
		return 1;

	spin_lock(&sulog_lock);
	memcpy(tmp_buf, sulog_buf_ptr, SULOG_BUFSIZ);
	tmp_index = sulog_index_next;
	spin_unlock(&sulog_lock);

	if (copy_to_user((void __user *)sbuf.index_ptr, &tmp_index, sizeof(tmp_index))) {
		kfree(tmp_buf);
		return 1;
	}

	if (copy_to_user((void __user *)sbuf.buf_ptr, tmp_buf, SULOG_BUFSIZ)) {
		kfree(tmp_buf);
		return 1;
	}

	kfree(tmp_buf);
	return 0;
}

void sulog_exit_heap(void)
{
	spin_lock(&sulog_lock);
	kfree(sulog_buf_ptr);
	sulog_buf_ptr = NULL;
	spin_unlock(&sulog_lock);
}
