#ifndef _OFFLOAD_OPS_H
#define _OFFLOAD_OPS_H

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "datapath.h"
#include "flow.h"
#include "vport.h"

struct ovs_offload_ops {
	char *handler_id;   /* Hardware vendor identifier */
	/* Flow offload functions  */
	/* Called when a flow entry is added to the flow table */
	int (*flow_new)(struct sw_flow *);
	/* Called when a flow entry is modified */
	int (*flow_set)(struct sw_flow *);
	/* Called when a flow entry is removed from the flow table */
	int (*flow_del)(struct sw_flow *);
	/* Called when a flow entry is queried */
	int (*flow_stats_get)(const struct sw_flow *, struct ovs_flow_stats *,
			      unsigned long *);
	/* Called when flow stats are removed */
	int (*flow_stats_clear)(struct sw_flow *);

	/* Port offload functions  */
	/* Called when a port is added to the datapath */
	int (*vport_new)(struct sk_buff *, struct vport *,
			 const struct vport_parms *);
	/* Called when a port is modified */
	int (*vport_set)(struct sk_buff *, struct vport *);
	/* Called when a port is removed from the datapath */
	int (*vport_del)(struct sk_buff *, struct vport *);
	/* Called when port stats are queried */
	int (*vport_stats_get)(const struct vport *, struct ovs_vport_stats *);

	/* Datapath offload functions  */
	/* Called when the datapath is created */
	int (*dp_new)(struct datapath *);
	/* Called when the datapath is modified */
	int (*dp_set)(struct datapath *);
	/* Called when the datapath is removed */
	int (*dp_del)(const struct datapath *);
	/* Called when the datapath stats are queried */
	int (*dp_stats_get)(const struct datapath *, struct ovs_dp_stats *);
};

extern struct ovs_offload_ops *offload_ops;

int ovs_offload_init_handler(void);
int ovs_offload_register(const struct ovs_offload_ops *new_handler);
int ovs_offload_unregister(void);
void ovs_offload_cleanup_handler(void);

/* Wrappers for calling offload function with locking in place */
/* Flow offload functions */
static inline void ovs_offload_flow_new(struct sw_flow *flow)
{
	struct ovs_offload_ops *offload =
	    rcu_dereference(offload_ops);

	if (offload && offload->flow_new)
		offload->flow_new(flow);
}

static inline void ovs_offload_flow_set(struct sw_flow *flow)
{
	struct ovs_offload_ops *offload =
	    rcu_dereference(offload_ops);

	if (offload && offload->flow_set)
		offload->flow_set(flow);
}

static inline void ovs_offload_flow_del(struct sw_flow *flow)
{
	struct ovs_offload_ops *offload =
	    rcu_dereference(offload_ops);

	if (offload && offload->flow_del)
		offload->flow_del(flow);
}

static inline void ovs_offload_flow_stats_get(const struct sw_flow *flow,
					      struct ovs_flow_stats *stats,
					      unsigned long *used,
					      __be16 *tcp_flags)
{
	struct ovs_offload_ops *offload =
	    rcu_dereference(offload_ops);

	if (offload && offload->flow_stats_get)
		offload->flow_stats_get(flow, stats, used);
}

static inline void ovs_offload_flow_stats_clear(struct sw_flow *flow)
{
	struct ovs_offload_ops *offload =
	    rcu_dereference(offload_ops);

	if (offload && offload->flow_stats_clear)
		offload->flow_stats_clear(flow);
}

/* Port offload functions */
static inline void ovs_offload_vport_new(struct sk_buff *skb, struct vport *vport,
					 const struct vport_parms *parms)
{
	struct ovs_offload_ops *offload =
	    rcu_dereference(offload_ops);

	if (offload && offload->vport_new)
		offload->vport_new(skb, vport, parms);
}

static inline void ovs_offload_vport_set(struct sk_buff *skb, struct vport *vport,
					 const struct vport_parms *parms)
{
	struct ovs_offload_ops *offload =
	    rcu_dereference(offload_ops);

	if (offload && offload->vport_set)
		offload->vport_set(skb, vport);
}

static inline void ovs_offload_vport_del(struct sk_buff *skb,
					 struct vport *vport,
					 const struct vport_parms *parms)
{
	struct ovs_offload_ops *offload =
	    rcu_dereference(offload_ops);

	if (offload && offload->vport_del)
		offload->vport_del(skb, vport);
}

static inline void ovs_offload_vport_stats_get(const struct vport *vport,
					       struct ovs_vport_stats *vport_stats)
{
	struct ovs_offload_ops *offload =
	    rcu_dereference(offload_ops);

	if (offload && offload->vport_stats_get)
		offload->vport_stats_get(vport, vport_stats);
}

/* Datapath offload functions */
static inline void ovs_offload_dp_new(struct datapath *dp)
{
	struct ovs_offload_ops *offload =
	    rcu_dereference(offload_ops);

	if (offload && offload->dp_new)
		offload->dp_new(dp);
}

static inline void ovs_offload_dp_set(struct datapath *dp)
{
	struct ovs_offload_ops *offload =
	    rcu_dereference(offload_ops);

	if (offload && offload->dp_set)
		offload->dp_set(dp);
}

static inline void ovs_offload_dp_del(const struct datapath *dp)
{
	struct ovs_offload_ops *offload =
	    rcu_dereference(offload_ops);

	if (offload && offload->dp_del)
		offload->dp_del(dp);
}

static inline void ovs_offload_dp_stats_get(const struct datapath *dp,
					    struct ovs_dp_stats *stats)
{
	struct ovs_offload_ops *offload =
	    rcu_dereference(offload_ops);

	if (offload && offload->dp_stats_get)
		offload->dp_stats_get(dp, stats);
}

#endif /* offload_ops.h */
