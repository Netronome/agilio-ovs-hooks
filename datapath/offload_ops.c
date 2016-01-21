#include "offload_ops.h"

struct ovs_offload_ops *offload_ops;

int ovs_offload_register(const struct ovs_offload_ops *new_handler)
{
	struct ovs_offload_ops *offload =
	    rcu_dereference(offload_ops);

	if (offload)
		return -EBUSY;
	offload = kmalloc(sizeof(*offload), GFP_KERNEL);
	if (!offload)
		return -ENOMEM;
	*offload = *new_handler;

	rcu_assign_pointer(offload_ops, offload);
	return 0;
}

EXPORT_SYMBOL(ovs_offload_register);

int ovs_offload_unregister()
{
	struct ovs_offload_ops *offload =
	    rcu_dereference(offload_ops);

	if (offload) {
		rcu_assign_pointer(offload_ops, NULL);
		kfree(offload);
	}
	return 0;
}

EXPORT_SYMBOL(ovs_offload_unregister);

int ovs_offload_init_handler(void)
{
	rcu_assign_pointer(offload_ops, NULL);
	return 0;
}

void ovs_offload_cleanup_handler(void)
{
	struct ovs_offload_ops *offload =
	    rcu_dereference(offload_ops);

	if (offload)
		kfree(offload);
	rcu_assign_pointer(offload_ops, NULL);
}

