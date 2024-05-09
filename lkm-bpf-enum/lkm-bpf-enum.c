#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/bpf.h>
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
#include <linux/idr.h>
#include <linux/spinlock.h>
// in kernel version 5.4, bpf_prog struct is defined in linux/filter.h
#include <linux/filter.h>
#include <uapi/linux/btf.h>
#include <linux/btf.h>
#include <linux/version.h>

// copied from Linux kernel source code (5.4)
struct btf {
	void *data;
	struct btf_type **types;
	u32 *resolved_ids;
	u32 *resolved_sizes;
	const char *strings;
	void *nohdr_data;
	struct btf_header hdr;
	u32 nr_types;
	u32 types_size;
	u32 data_size;
	refcount_t refcnt;
	u32 id;
	struct rcu_head rcu;
};

struct idr *prog_idr;
spinlock_t *prog_idr_lock;

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

typedef struct bpf_prog *(*bpf_prog_get_curr_or_next_t)(u32 *);

// copied from Linux kernel source code (5.4)
static const struct btf_type *my_btf_type_by_id(const struct btf *btf, u32 type_id)
{
	if (type_id > btf->nr_types)
		return NULL;

	return btf->types[type_id];
}

// copied from Linux kernel source code (5.4)
static const char *my_btf_name_by_offset(const struct btf *btf, u32 offset)
{
	if (offset < btf->hdr.str_len)
		return &btf->strings[offset];

	return NULL;
}

//// copied from Linux kernel source code (6.7.4)
//static struct bpf_prog *my_bpf_prog_inc_not_zero(struct bpf_prog *prog)
//{
//	int refold;
//
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
//	refold = atomic64_fetch_add_unless(&prog->aux->refcnt, 1, 0);
//#else
//	// in kernel 5.4 and earlier, refcnt is of type atomic_t and not atomic64_t
//	refold = atomic_fetch_add_unless(&prog->aux->refcnt, 1, 0);
//#endif
//
//	if (!refold)
//		return ERR_PTR(-ENOENT);
//
//	return prog;
//}

// copy pasted from Linux kernel source code (6.7.4)
static struct bpf_prog *my_bpf_prog_get_curr_or_next(u32 *id)
{
	struct bpf_prog *prog;

	spin_lock_bh(prog_idr_lock);
again:
	prog = idr_get_next(prog_idr, id);
	if (prog) {
		// XXX we do not increment the refcnt, otherwise the program
		// would not be unloaded even when the user space rootkit exits
		//prog = my_bpf_prog_inc_not_zero(prog);
		if (IS_ERR(prog)) {
			(*id)++;
			goto again;
		}
	}
	spin_unlock_bh(prog_idr_lock);

	return prog;
}
 
static int  __init lkm_bpf_enum_init(void) 
{ 
	u32 i;
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;

	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);

	prog_idr = (struct idr *) kallsyms_lookup_name("prog_idr");
	prog_idr_lock = (spinlock_t *) kallsyms_lookup_name("prog_idr_lock");
	if (!prog_idr || !prog_idr_lock) {
		pr_info("prog_idr or prog_idr_lock not found\n");
		return 0;
	}

	pr_info("prog_idr @ %p\n", prog_idr);

	pr_info("bpf prog list using prog_idr\n");
	for (i = 0; ; i++) {
		struct bpf_prog *prog = my_bpf_prog_get_curr_or_next(&i);
		const char *name;

		if (!prog) {
			break;
		}

		name = prog->aux->name;
		
		// try to retrieve the full name
		// copied from Linux kernel source code (github 2024-02-18)
		if (prog->aux->func_info_cnt && prog->aux->func_idx < prog->aux->func_info_cnt) {
			const struct btf_type *type = my_btf_type_by_id(prog->aux->btf,
					prog->aux->func_info[prog->aux->func_idx].type_id);

			name = my_btf_name_by_offset(prog->aux->btf, type->name_off);
			pr_info("BTF available\n");
		}

		pr_info("  %u: %s\n", i, name); 
		
		i++;
	}

	return 0; 
} 

static void __exit lkm_bpf_enum_exit(void) 
{ 
} 

module_init(lkm_bpf_enum_init);
module_exit(lkm_bpf_enum_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("petostr"); 
MODULE_DESCRIPTION("BPF program list");
