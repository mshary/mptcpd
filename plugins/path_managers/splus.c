// SPDX-License-Identifier: BSD-3-Clause
/**
 * @file splus.c
 *
 * @brief MPTCP splus path manager plugin.
 *
 * Copyright (c) 2018, 2019, Burraq Technologies UG
 */

#include <assert.h>
#include <stddef.h>  // For NULL.
#include <limits.h>

#include <stdlib.h>     // For malloc.
#include <arpa/inet.h>	// For inet_ntop
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netdb.h>

#include <netinet/in.h>

#include <ell/plugin.h>
#include <ell/util.h>  // For L_STRINGIFY needed by l_error().
#include <ell/log.h>
#include <ell/queue.h>

#ifdef HAVE_CONFIG_H
# include <mptcpd/config-private.h>   // For mptcpd VERSION.
#endif

#include <mptcpd/network_monitor.h>
#include <mptcpd/path_manager.h>
#include <mptcpd/plugin.h>

#include <hiredis/hiredis.h>

/**
 * @brief Local address to interface mapping failure value.
 */
#define SPLUS_BAD_INDEX INT_MAX

#define REDIS_HOST "127.0.0.1"
#define REDIS_PORT 6379
#define REDIS_EXPIRE 3600

/**
 * @struct splus_interface_info
 *
 * @brief Network interface information.
 *
 * This plugin tracks MPTCP connection tokens on each network
 * interface.  A network interface is represented by its kernel
 * assigned index value, which is based on the local address of the
 * subflow.  Once the network interface corresponding to the subflow
 * local address is determined, the connection token for that subflow
 * is then associated with the network interface as a means to denote
 * that the MPTCP connection has a subflow on that network interface.
 */
struct splus_interface_info
{
	/**
	 * @brief Network interface index.
	 */
	int index;

	/**
	 * @brief List of MPTCP connection tokens.
	 */
	struct l_queue *tokens;
};

/**
 * @struct splus_new_connection_info
 *
 * @brief Package @c new_connection() plugin operation arguments.
 *
 * This is a convenience structure for the purpose of making it easy
 * to pass @c new_connection() plugin operation arguments through
 * a single variable.
 */
struct splus_new_connection_info 
{
	/** 
	 * @brief MPTCP connection token.
	 */
	mptcpd_token_t const token;

	/** 
	 * @brief MPTCP local connection socket.
	 */
	struct sockaddr const *laddr;

	/** 
	 * @brief MPTCP remote connection socket.
	 */
	struct sockaddr const *raddr;

	/** 
	 * @brief Pointer to path manager.
	 */
	struct mptcpd_pm *const pm;
};

// ----------------------------------------------------------------

static char* get_addr(struct sockaddr const *res) 
{
	char *s = NULL;
	switch(res->sa_family) 
	{
		case AF_INET: 
		{
			struct sockaddr_in *addr_in = 
				(struct sockaddr_in *)res;
			s = malloc(INET_ADDRSTRLEN);
			inet_ntop(AF_INET, 
					&(addr_in->sin_addr), 
					s, 
					INET_ADDRSTRLEN);
			break;
		}
		case AF_INET6: 
		{
			struct sockaddr_in6 *addr_in6 = 
				(struct sockaddr_in6 *)res;
			s = malloc(INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6, 
					&(addr_in6->sin6_addr), 
					s, 
					INET6_ADDRSTRLEN);
			break;
		}
		default:
			break;
	}
	return s;
}

/**
 * @brief Match a @c sockaddr object.
 *
 * A network address represented by @a a (@c struct @c sockaddr)
 * matches if its @c family and @c addr members match those in the
 * @a b.
 *
 * @param[in] a Currently monitored network address of type @c struct
 *              @c sockaddr*.
 * @param[in] b Network address of type @c struct @c sockaddr*
 *              to be compared against network address @a a.
 *
 * @return @c true if the network address represented by @a a matches
 *         the address @a b, and @c false otherwise.
 *
 * @see l_queue_find()
 * @see l_queue_remove_if()
 */
static bool splus_sockaddr_match(void const *a, 
		void const *b) 
{
	struct sockaddr const *const lhs = a;
	struct sockaddr const *const rhs = b;

	assert(lhs);
	assert(rhs);
	assert(lhs->sa_family == AF_INET || 
			lhs->sa_family == AF_INET6);

	bool matched = (lhs->sa_family == rhs->sa_family);

	if (!matched) 
	{
		return matched;
	}

	if (lhs->sa_family == AF_INET) 
	{
		struct sockaddr_in const *const l =
			(struct sockaddr_in const *) lhs;
		struct sockaddr_in const *const r =
			(struct sockaddr_in const *) rhs;

		matched = (l->sin_addr.s_addr == r->sin_addr.s_addr);

	} else {
		struct sockaddr_in6 const *const l =
			(struct sockaddr_in6 const *) lhs;
		struct sockaddr_in6 const *const r =
			(struct sockaddr_in6 const *) rhs;

		matched = (memcmp(&l->sin6_addr, 
					&r->sin6_addr, 
					sizeof(l->sin6_addr)) 
				== 0);
	}

	return matched;
}

// ----------------------------------------------------------------

/**
 * @struct splus_nm_callback_data
 *
 * @brief Type used to return index associated with local address.
 *
 * @see @c mptcpd_nm_callback
 */
struct splus_nm_callback_data 
{
	/**
	 * @brief Local address information.        (IN)
	 */
	struct sockaddr const* const addr;

	/**
	 * @brief Network interface (link) index.   (OUT)
	 */
	int index;
};

// ----------------------------------------------------------------

/**
 * @brief Inform kernel of local address available for subflows.
 *
 * @param[in] i    Network interface information.
 * @param[in] data User supplied data, the path manager in this case.
 */
static void splus_send_addr(void *data, 
		void *user_data) 
{
	struct sockaddr                 const *const addr = data;
	struct splus_new_connection_info const *const info = user_data;

	/**
	 * @bug Use real values instead of these placeholders!  The
	 *      @c port, in particular, is problematic because no
	 *      subflows exist for the addr in question, meaning there
	 *      is no port associated with it.
	 */
	mptcpd_aid_t address_id = 0;

	/**
	 * @note The port is an optional field of the MPTCP
	 *       @c ADD_ADDR option.  Setting it to zero causes it to
	 *       be ignored when sending the address information to
	 *       the kernel.
	 */
	in_port_t const port = 0;

	if (addr->sa_family == AF_INET) 
	{
		((struct sockaddr_in*) addr)->sin_port = port;
	} else {
		((struct sockaddr_in6*) addr)->sin6_port = port;
	}

	if (!splus_sockaddr_match(addr, info->laddr) && 
			(addr->sa_family == info->raddr->sa_family)) 
	{
		l_info("Broadcasting to %s", get_addr(addr));
		mptcpd_pm_send_addr(info->pm, info->token, address_id, addr);
	};
}

/**
 * @brief Inform kernel of network interface usable local addresses.
 *
 * Send all local addresses associated with the given network
 * interface if that interface doesn't already have the initial
 * subflow on it.
 *
 * @param[in] i    Network interface information.
 * @param[in] data User supplied data, the path manager in this case.
 */
static void splus_send_addrs(struct mptcpd_interface const *i, 
		void *data) 
{
	l_debug("interface\n"
			"  family: %d\n"
			"  type:   %d\n"
			"  index:  %d\n"
			"  flags:  0x%08x\n"
			"  name:   %s",
			i->family,
			i->type,
			i->index,
			i->flags,
			i->name);

	struct splus_new_connection_info *const info = data;

	/* 
	 * Send each address associate with the network 
	 * interface.
	 */
	l_queue_foreach(i->addrs, splus_send_addr, info);
}

static void splus_broadcast(mptcpd_token_t token,
		struct sockaddr const *laddr,
		struct sockaddr const *raddr,
		struct mptcpd_pm *pm) 
{
	/**
	 * @note The kernel always provides non-zero MPTCP connection
	 *		 tokens.
	 */
	assert(token != 0);

	struct mptcpd_nm const *const nm = mptcpd_pm_get_nm(pm);

	/* 
	 * Inform the kernel of additional local addresses available 
	 * for subflows, e.g. for MP_JOIN purposes.
	 */
	struct splus_new_connection_info connection_info = 
	{
		.token = token,
		.laddr = laddr,
		.raddr = raddr,
		.pm    = pm
	};

	mptcpd_nm_foreach_interface(nm, 
			splus_send_addrs, 
			&connection_info);
}

// ----------------------------------------------------------------
//                     Mptcpd Plugin Operations
// ----------------------------------------------------------------

static void splus_new_connection(mptcpd_token_t token,
		struct sockaddr const *laddr,
		struct sockaddr const *raddr,
		struct mptcpd_pm *pm) 
{
	(void) raddr;

	assert(token != 0);

	struct timeval timeout = { 1, 500000 }; // 1.5 seconds
	redisContext *c;
	redisReply *reply;

	splus_broadcast(token, laddr, raddr, pm);

	l_info("%s: new connection from %s to %s ", __func__,
			get_addr(laddr),
			get_addr(raddr));

	c = redisConnectWithTimeout(REDIS_HOST, REDIS_PORT, timeout);

	if (c != NULL && !c->err) 
	{
		reply = redisCommand(c,
				"HMSET mptcp-token-%d laddr %s raddr %s",
				token, 
				get_addr(laddr), 
				get_addr(raddr));

		l_info("redis HMSET: %s\n", reply->str);
		freeReplyObject(reply);

		reply = redisCommand(c, 
				"EXPIRE mptcp-token-%d %d", 
				token, 
				REDIS_EXPIRE);
		freeReplyObject(reply);
	}

	redisFree(c);
}

static void splus_connection_established(mptcpd_token_t token,
		struct sockaddr const *laddr,
		struct sockaddr const *raddr,
		struct mptcpd_pm *pm) 
{
	(void) raddr;

	assert(token != 0);

	if (0)	// do we need to broardcast this?
		splus_broadcast(token, laddr, raddr, pm);

	l_info("%s: connection established from %s to %s ", __func__,
			get_addr(laddr),
			get_addr(raddr));
}

static void splus_connection_closed(mptcpd_token_t token,
		struct mptcpd_pm *pm) 
{
	(void) token;
	(void) pm;

	struct timeval timeout = { 1, 500000 }; // 1.5 seconds
	redisContext *c;
	redisReply *reply;

	c = redisConnectWithTimeout(REDIS_HOST, REDIS_PORT, timeout);

	if (c != NULL && !c->err) 
	{
		reply = redisCommand(c,
				"DEL mptcp-token-%d", 
				token);
		freeReplyObject(reply);
	}

	redisFree(c);
}

static void splus_new_address(mptcpd_token_t token,
		mptcpd_aid_t id,
		struct sockaddr const *addr,
		struct mptcpd_pm *pm) 
{
	(void) token;
	(void) id;
	(void) pm;

	struct timeval timeout = { 1, 500000 }; // 1.5 seconds
	redisContext *c;
	redisReply *reply;

	mptcpd_pm_send_addr(pm, token, 0, addr);

	c = redisConnectWithTimeout(REDIS_HOST, REDIS_PORT, timeout);

	if (c != NULL && !c->err) 
	{
		reply = redisCommand(c, 
				"SADD mptcp-addresses %s", 
				get_addr(addr));
		freeReplyObject(reply);
	}

	redisFree(c);
}

static void splus_address_removed(mptcpd_token_t token,
		mptcpd_aid_t id,
		struct mptcpd_pm *pm) 
{
	(void) id;
	(void) pm;

	struct timeval timeout = { 1, 500000 }; // 1.5 seconds
	redisContext *c;
	redisReply *reply;
	char *laddr;

	c = redisConnectWithTimeout(REDIS_HOST, REDIS_PORT, timeout);

	if (c != NULL && !c->err) 
	{
		reply = redisCommand(c, 
				"HGET mptcp-token-%d laddr", 
				token);
		laddr = reply->str;
		freeReplyObject(reply);

		reply = redisCommand(c, "SREM mptcp-addresses %s", laddr);
		freeReplyObject(reply);
	}

	redisFree(c);
}

static void splus_new_subflow(mptcpd_token_t token,
		struct sockaddr const *laddr,
		struct sockaddr const *raddr,
		bool backup,
		struct mptcpd_pm *pm) 
{
	(void) token;
	(void) backup;
	(void) pm;

	l_info("%s: new subflow from %s to %s ", __func__,
			get_addr(laddr),
			get_addr(raddr));
}

static void splus_subflow_closed(mptcpd_token_t token,
		struct sockaddr const *laddr,
		struct sockaddr const *raddr,
		bool backup,
		struct mptcpd_pm *pm) 
{
	(void) token;
	(void) backup;
	(void) pm;

	l_info("%s: subflow closed from %s to %s ", __func__,
			get_addr(laddr),
			get_addr(raddr));
}

static void splus_subflow_priority(mptcpd_token_t token,
		struct sockaddr const *laddr,
		struct sockaddr const *raddr,
		bool backup,
		struct mptcpd_pm *pm)
{
	(void) token;
	(void) laddr;
	(void) raddr;
	(void) backup;
	(void) pm;

	/* 
	 * The splus plugin doesn't do anything with changes in subflow 
	 * priority.
	 */
	l_warn("%s is unimplemented.", __func__);
}

static struct mptcpd_plugin_ops const pm_ops = 
{
	.new_connection         = splus_new_connection,
	.connection_established = splus_connection_established,
	.connection_closed      = splus_connection_closed,
	.new_address            = splus_new_address,
	.address_removed        = splus_address_removed,
	.new_subflow            = splus_new_subflow,
	.subflow_closed         = splus_subflow_closed,
	.subflow_priority       = splus_subflow_priority
};

static int splus_init(void) 
{
	static char const name[] = "splus";

	struct ifaddrs *addrs,*tmp;
	char host[NI_MAXHOST];
	int s;

	if (!mptcpd_plugin_register_ops(name, &pm_ops)) {
		l_error("%s: Failed to initialize splus "
				"path manager plugin.", __func__);
		return -1;
	}

	getifaddrs(&addrs);
	tmp = addrs;

	while (tmp) {
		if (tmp->ifa_addr && 
				((tmp->ifa_addr->sa_family == AF_INET) || 
				(tmp->ifa_addr->sa_family == AF_INET6)))
		{
			s = getnameinfo(tmp->ifa_addr,
					(tmp->ifa_addr->sa_family == AF_INET) ? 
					sizeof(struct sockaddr_in) :
					sizeof(struct sockaddr_in6),
					host, NI_MAXHOST,
					NULL, 0, NI_NUMERICHOST);
			if (s == 0) 
			{
				l_info("%s: Found interface %s "
						"with IP address %s", 
						__func__, 
						tmp->ifa_name, 
						host);
			}
		}

		tmp = tmp->ifa_next;
	}

	freeifaddrs(addrs);

	l_info("MPTCP splus path manager initialized.");
	return 0;
}

static void splus_exit(void)
{
	l_info("MPTCP splus path manager exited.");
}

L_PLUGIN_DEFINE(MPTCPD_PLUGIN_DESC,
		splus,
		"SPlus path manager",
		VERSION,
		L_PLUGIN_PRIORITY_DEFAULT,
		splus_init,
		splus_exit)

/*
   Local Variables:
   c-file-style: "linux"
   End:
*/
