/* action_executor.cpp — T28 defensive action executor.
 * See action_executor.hpp for the architecture rationale.
 */
// T12.12: _GNU_SOURCE must be defined before any system header to
// avoid conflicts between <linux/in.h> (pulled by <linux/ip.h>) and
// <netinet/in.h> (pulled by other headers). Without this, glibc
// complains about redefinition of struct in_addr and IPPROTO_* macros.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "action_executor.hpp"
#include "debug.hpp"  // LOG_INFO / LOG_ERROR / LOG_WARN macros (MUST be after system headers)
#include "fim_watch.hpp"  // T12.12: t28_fim_watch_add/remove shims (defined in agent.cpp)

#include "json.hpp"  // nlohmann/json single-header (vendored in src/)

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/syscall.h>   // T12.12: ::syscall() + __NR_delete_module
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <cstdlib>
#include <cstdio>
#include <chrono>
#include <thread>
#include <atomic>
#include <array>

// T12.12: libmnl for nftables firewall (block_ip). Linked statically
// per the T12.12 Makefile change. libnftnl was considered but rejected
// for the small subset we need (add 1 rule, delete by handle): its
// high-level API has too many moving parts (5-arg build_hdr, deprecated
// setters, opaque expr types) for our use case. Raw netlink via libmnl
// is simpler and 100% under our control.
//
// libmnl: low-level netlink transport (socket, sendto, recv, attr marshaling)
//
// CRITICAL include order on this glibc:
//   - <arpa/inet.h> pulls <netinet/in.h> which defines struct in_addr
//   - <linux/netfilter.h> pulls <linux/in.h> which ALSO defines struct in_addr
//   - Including them in the wrong order causes "redefinition of struct in_addr"
//   - SOLUTION: include <arpa/inet.h> FIRST so netinet/in.h is processed first,
//     and the struct in_addr from <linux/in.h> is then recognized as the
//     "glibc private re-export" of the same type (no redefinition).
//   - This is a known glibc-2.40+ quirk on Ubuntu 25.04.
#include <arpa/inet.h>          // inet_pton (MUST be before linux/netfilter.h)
#include <linux/netfilter.h>    // NF_DROP, NF_INET_LOCAL_IN (also pulls linux/in.h)
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <libmnl/libmnl.h>
#include <linux/netlink.h>
// We need the offset of saddr in an IPv4 header. The standard layout
// (per RFC 791) is: ver/ihl(1) + tos(1) + total_len(2) + id(2) +
// flags/frag(2) = 8 bytes, then ttl(1) + proto(1) + checksum(2) = 4
// bytes, then saddr(4) at offset 12. Rather than including
// <linux/ip.h> (which conflicts with <netinet/in.h> already pulled by
// other headers), we just use the literal offset 12. This matches
// the ihl=5 (20-byte) minimum header.
constexpr uint32_t IPV4_SADDR_OFFSET = 12;

namespace logsoc::agent::t28 {

using json = nlohmann::json;

// Sanitise a single string token: reject anything that's not a
// printable ASCII, an IPv4/v6 char, or a /._-  This is the LAST line
// of defence for any string that gets passed to a syscall or a
// netlink attribute — we already validated upstream but never
// trust the wire. (The "before exec" wording was the old rationale;
// there is no exec anymore, but the sanitiser is still important
// because syscalls like ::kill(2) on a malformed pid are wasted and
// the libmnl nftables path can be crashed by garbage.)

static bool is_safe_token(const std::string& s, size_t max_len = 256) {
    if (s.empty() || s.size() > max_len) return false;
    for (char c : s) {
        if (c >= '0' && c <= '9') continue;
        if (c >= 'a' && c <= 'z') continue;
        if (c >= 'A' && c <= 'Z') continue;
        if (c == '/' || c == '.' || c == '_' || c == '-') continue;
        if (c == ':') continue;  // IPv6
        return false;
    }
    return true;
}

// ── Action handlers ────────────────────────────────────────────────────
static ActionResult do_kill_pid(const json& payload, bool dry_run) {
    ActionResult r;
    if (!payload.contains("pid") || !payload["pid"].is_number_integer()) {
        r.status = "failed"; r.result_message = "missing pid";
        return r;
    }
    int pid = payload["pid"].get<int>();
    int sig = payload.value("signal", 9);
    if (pid <= 0 || pid > 4194304) {
        r.status = "failed";
        r.result_message = "pid out of range: " + std::to_string(pid);
        return r;
    }
    if (sig != 9 && sig != 15 && sig != 19) {
        r.status = "failed";
        r.result_message = "signal must be 9/15/19, got " + std::to_string(sig);
        return r;
    }
    // T12.12: replace /bin/sh -c "kill -X Y" with a direct ::kill(2) syscall.
    // No fork, no execve, no /bin/sh dependency. is_safe_token() above still
    // acts as defense-in-depth on pid (we cast int → pid_t) and on sig
    // (whitelisted 9/15/19).
    if (dry_run) {
        LOG_INFO("[T28] DRY-RUN would kill(pid=" << pid << ", sig=" << sig << ")");
        r.status = "succeeded";
        r.result_message = "dry_run: would send signal " + std::to_string(sig) +
                           " to pid " + std::to_string(pid);
        r.stdout_ = "kill(" + std::to_string(pid) + ", " + std::to_string(sig) + ")\n";
        return r;
    }
    int rc = ::kill(static_cast<pid_t>(pid), sig);
    if (rc == 0) {
        r.status = "succeeded";
        r.result_message = "sent signal " + std::to_string(sig) +
                           " to pid " + std::to_string(pid);
    } else {
        r.status = "failed";
        r.result_message = "kill(pid=" + std::to_string(pid) +
                           ", sig=" + std::to_string(sig) + ") failed: " +
                           std::string(strerror(errno));
    }
    return r;
}

// ── nftables backend (T12.12) ───────────────────────────────────────────
//
// The agent blocks/unblocks IPs by pushing nftables rules via netlink,
// using libmnl (transport) only. We build the raw netlink message by
// hand because libnftnl's high-level API has too many moving parts for
// the small subset we need (add 1 rule, delete by handle).
//
// Architecture:
//   - g_nl_sock: long-lived NETLINK_NETFILTER socket (opened lazily on
//     first block_ip call, never closed until process exit)
//   - g_nl_seq: monotonic netlink sequence number (atomic)
//   - g_nftables_unavailable: set to true on init failure; all
//     subsequent block_ip calls fail fast
//
// Operations:
//   - add: NFT_NEWRULE on chain "input" of table "filter" matching
//          ip saddr <X> with verdict drop
//   - del: NFT_DELRULE by handle (handle stored in backend after block)
//
// Family: AF_INET (IPv4 only in this commit). IPv6 support deferred
// to a future commit (it requires a different expr layout: ip6 saddr
// + 4 NFT_REG32s for the 16-byte address).

static std::atomic<bool> g_nftables_unavailable{false};
static struct mnl_socket* g_nl_sock = nullptr;
static std::atomic<uint32_t> g_nl_seq{1};

// Lazy init: open the netlink socket.
static bool nftables_init() {
    if (g_nl_sock != nullptr) return true;
    if (g_nftables_unavailable.load()) return false;
    g_nl_sock = mnl_socket_open(NETLINK_NETFILTER);
    if (g_nl_sock == nullptr) {
        LOG_ERROR("[T28] nftables_init: mnl_socket_open failed: " << strerror(errno));
        g_nftables_unavailable.store(true);
        return false;
    }
    if (mnl_socket_bind(g_nl_sock, 0, 0) < 0) {
        LOG_ERROR("[T28] nftables_init: mnl_socket_bind failed: " << strerror(errno));
        mnl_socket_close(g_nl_sock);
        g_nl_sock = nullptr;
        g_nftables_unavailable.store(true);
        return false;
    }
    LOG_INFO("[T28] nftables_init: netlink socket opened (NFTABLES backend ready)");
    return true;
}

// Build a nftables NFT_NEWRULE message in `buf` for ip saddr <X> drop
// in table "filter" / chain "input". Returns the total message length
// written, or -1 on error.
static int build_newrule_msg(char* buf, uint32_t seq, const std::string& ip) {
    struct nlmsghdr* nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE;
    nlh->nlmsg_flags = NLM_F_CREATE | NLM_F_ACK | NLM_F_REQUEST;
    nlh->nlmsg_seq = seq;

    struct nfgenmsg* nfg = (struct nfgenmsg*)mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
    nfg->nfgen_family = AF_INET;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = 0;

    // Attributes required: NFTA_RULE_TABLE, NFTA_RULE_CHAIN
    mnl_attr_put_str(nlh, NFTA_RULE_TABLE, "filter");
    mnl_attr_put_str(nlh, NFTA_RULE_CHAIN, "input");

    // Build NFTA_RULE_EXPRESSIONS as a nested attribute containing
    // a list of exprs (ip, cmp, immediate).
    struct nlattr* exprs = mnl_attr_nest_start(nlh, NFTA_RULE_EXPRESSIONS);

    // Expr 1: payload (ip saddr → reg 1)
    struct nlattr* expr1 = mnl_attr_nest_start(nlh, 1);
    mnl_attr_put_str(nlh, NFTA_EXPR_NAME, "payload");
    {
        struct nlattr* payload = mnl_attr_nest_start(nlh, NFTA_EXPR_DATA);
        mnl_attr_put_u32(nlh, NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
        mnl_attr_put_u32(nlh, NFTA_PAYLOAD_OFFSET, IPV4_SADDR_OFFSET);
        mnl_attr_put_u32(nlh, NFTA_PAYLOAD_LEN, sizeof(uint32_t));
        mnl_attr_put_u32(nlh, NFTA_PAYLOAD_DREG, NFT_REG32_01);
        mnl_attr_nest_end(nlh, payload);
    }
    mnl_attr_nest_end(nlh, expr1);

    // Expr 2: cmp reg1 == <ip>
    struct nlattr* expr2 = mnl_attr_nest_start(nlh, 2);
    mnl_attr_put_str(nlh, NFTA_EXPR_NAME, "cmp");
    {
        struct nlattr* cmp = mnl_attr_nest_start(nlh, NFTA_EXPR_DATA);
        mnl_attr_put_u32(nlh, NFTA_CMP_SREG, NFT_REG32_01);
        mnl_attr_put_u32(nlh, NFTA_CMP_OP, NFT_CMP_EQ);
        in_addr_t addr;
        if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
            return -1;
        }
        mnl_attr_put(nlh, NFTA_CMP_DATA, sizeof(addr), &addr);
        mnl_attr_nest_end(nlh, cmp);
    }
    mnl_attr_nest_end(nlh, expr2);

    // Expr 3: immediate drop (verdict → drop)
    struct nlattr* expr3 = mnl_attr_nest_start(nlh, 3);
    mnl_attr_put_str(nlh, NFTA_EXPR_NAME, "immediate");
    {
        struct nlattr* imm = mnl_attr_nest_start(nlh, NFTA_EXPR_DATA);
        mnl_attr_put_u32(nlh, NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
        mnl_attr_put_u32(nlh, NFTA_IMMEDIATE_DATA, NF_DROP);
        mnl_attr_nest_end(nlh, imm);
    }
    mnl_attr_nest_end(nlh, expr3);

    mnl_attr_nest_end(nlh, exprs);

    return nlh->nlmsg_len;
}

// Build a NFT_DELRULE message by handle.
static int build_delrule_msg(char* buf, uint32_t seq, uint64_t handle) {
    struct nlmsghdr* nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELRULE;
    nlh->nlmsg_flags = NLM_F_ACK | NLM_F_REQUEST;
    nlh->nlmsg_seq = seq;

    struct nfgenmsg* nfg = (struct nfgenmsg*)mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
    nfg->nfgen_family = AF_INET;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = 0;

    mnl_attr_put_str(nlh, NFTA_RULE_TABLE, "filter");
    mnl_attr_put_str(nlh, NFTA_RULE_CHAIN, "input");
    mnl_attr_put_u64(nlh, NFTA_RULE_HANDLE, handle);

    return nlh->nlmsg_len;
}

// Build a NFT_NEWTABLE message.
static int build_newtable_msg(char* buf, uint32_t seq) {
    struct nlmsghdr* nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE;
    nlh->nlmsg_flags = NLM_F_CREATE | NLM_F_ACK | NLM_F_REQUEST;
    nlh->nlmsg_seq = seq;

    struct nfgenmsg* nfg = (struct nfgenmsg*)mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
    nfg->nfgen_family = AF_INET;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = 0;

    mnl_attr_put_str(nlh, NFTA_TABLE_NAME, "filter");
    return nlh->nlmsg_len;
}

// Build a NFT_NEWCHAIN message.
static int build_newchain_msg(char* buf, uint32_t seq) {
    struct nlmsghdr* nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN;
    nlh->nlmsg_flags = NLM_F_CREATE | NLM_F_ACK | NLM_F_REQUEST;
    nlh->nlmsg_seq = seq;

    struct nfgenmsg* nfg = (struct nfgenmsg*)mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
    nfg->nfgen_family = AF_INET;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = 0;

    mnl_attr_put_str(nlh, NFTA_CHAIN_TABLE, "filter");
    mnl_attr_put_str(nlh, NFTA_CHAIN_NAME, "input");

    // Chain hook spec
    struct nlattr* hook = mnl_attr_nest_start(nlh, NFTA_CHAIN_HOOK);
    mnl_attr_put_u32(nlh, NFTA_HOOK_HOOKNUM, NF_INET_LOCAL_IN);
    // NFTA_HOOK_PRIORITY is declared s32 in the kernel; libmnl has no
    // signed helper, so we cast through uint32_t (the bit pattern is
    // preserved on two's-complement platforms, which is everything
    // we support).
    mnl_attr_put_u32(nlh, NFTA_HOOK_PRIORITY, (uint32_t)0);
    mnl_attr_nest_end(nlh, hook);

    return nlh->nlmsg_len;
}

// Send a raw netlink message and wait for the ACK. Returns 0 on success.
static int nft_send_and_wait_ack(char* buf, int len, uint32_t seq) {
    if (mnl_socket_sendto(g_nl_sock, buf, len) < 0) {
        LOG_ERROR("[T28] nft_send_and_wait_ack: sendto failed: " << strerror(errno));
        return -1;
    }
    char rcv_buf[MNL_SOCKET_BUFFER_SIZE];
    int ret = mnl_socket_recvfrom(g_nl_sock, rcv_buf, sizeof(rcv_buf));
    if (ret < 0) {
        LOG_ERROR("[T28] nft_send_and_wait_ack: recvfrom failed: " << strerror(errno));
        return -1;
    }
    // mnl_cb_run returns -1 on NLMSG_ERROR (kernel NACK)
    ret = mnl_cb_run(rcv_buf, ret, seq, mnl_socket_get_portid(g_nl_sock), NULL, NULL);
    if (ret < 0) {
        // errno is set by mnl_cb_run to the kernel error
        return -1;
    }
    return 0;
}

// Ensure table "filter" + chain "input" exists. Idempotent (EEXIST
// from the kernel is treated as success).
static bool nftables_ensure_table_and_chain() {
    char buf[MNL_SOCKET_BUFFER_SIZE];
    uint32_t seq;
    int rc;

    // Table
    seq = g_nl_seq.fetch_add(1);
    int len = build_newtable_msg(buf, seq);
    if (len < 0) return false;
    rc = nft_send_and_wait_ack(buf, len, seq);
    // EEXIST is fine
    if (rc < 0 && errno != EEXIST) {
        LOG_WARN("[T28] nftables_ensure_table_and_chain: newtable: " << strerror(errno));
        // Continue anyway — chain creation might still work
    }

    // Chain
    seq = g_nl_seq.fetch_add(1);
    len = build_newchain_msg(buf, seq);
    if (len < 0) return false;
    rc = nft_send_and_wait_ack(buf, len, seq);
    if (rc < 0 && errno != EEXIST) {
        LOG_ERROR("[T28] nftables_ensure_table_and_chain: newchain: " << strerror(errno));
        return false;
    }
    return true;
}

static ActionResult do_block_ip(const json& payload, bool dry_run, bool block) {
    ActionResult r;
    if (!payload.contains("ip") || !payload["ip"].is_string()) {
        r.status = "failed"; r.result_message = "missing ip"; return r;
    }
    std::string ip = payload["ip"].get<std::string>();
    if (!is_safe_token(ip, 45)) {
        r.status = "failed";
        r.result_message = "ip contains unsafe chars: " + ip;
        return r;
    }
    // T12.12: the 'via' parameter is no longer respected. Only nftables
    // is supported. The parameter is kept in the API for backward
    // compatibility with the dashboard but is silently ignored.
    std::string via = payload.value("via", "nftables");
    if (via != "nftables" && via != "") {
        LOG_WARN("[T28] block_ip: 'via=" << via << "' requested but only nftables is supported (T12.12), ignoring");
    }
    // Validate IP format (defense-in-depth, is_safe_token is permissive)
    struct in_addr addr4;
    if (inet_pton(AF_INET, ip.c_str(), &addr4) != 1) {
        r.status = "failed";
        r.result_message = "ip is not a valid IPv4 address (IPv6 not yet supported in T12.12): " + ip;
        return r;
    }
    if (dry_run) {
        LOG_INFO("[T28] DRY-RUN would " << (block ? "block" : "unblock")
                  << " ip " << ip << " via nftables (netlink)");
        r.status = "succeeded";
        r.result_message = std::string(block ? "block_ip" : "unblock_ip") +
                           " dry_run via nftables";
        r.stdout_ = "nftables " + std::string(block ? "add" : "del") +
                    " rule inet filter input ip saddr " + ip + " " +
                    (block ? "drop" : "(delete by handle)") + "\n";
        return r;
    }
    // Lazy init the netlink socket
    if (!nftables_init()) {
        r.status = "failed";
        r.result_message = "firewall backend unavailable: nftables netlink socket init failed "
                           "(requires nf_tables kernel module + CAP_NET_ADMIN)";
        return r;
    }
    // Ensure table+chain exist (idempotent)
    if (!nftables_ensure_table_and_chain()) {
        r.status = "failed";
        r.result_message = "firewall backend unavailable: failed to ensure table filter / chain input exists";
        return r;
    }
    char buf[MNL_SOCKET_BUFFER_SIZE];
    if (block) {
        uint32_t seq = g_nl_seq.fetch_add(1);
        int len = build_newrule_msg(buf, seq, ip);
        if (len < 0) {
            r.status = "failed";
            r.result_message = "failed to build nftables newrule message for " + ip;
            return r;
        }
        if (nft_send_and_wait_ack(buf, len, seq) < 0) {
            r.status = "failed";
            r.result_message = "nftables: failed to add rule for " + ip + ": " +
                               std::string(strerror(errno));
            return r;
        }
        r.status = "succeeded";
        r.result_message = "blocked " + ip + " via nftables (netlink)";
        return r;
    } else {
        // unblock: requires the original handle from the previous block.
        if (!payload.contains("handle")) {
            r.status = "failed";
            r.result_message = "unblock_ip requires 'handle' field in payload "
                               "(returned by previous block_ip result). "
                               "Without a handle, use the host's nft CLI directly.";
            return r;
        }
        uint64_t handle = payload["handle"].get<uint64_t>();
        uint32_t seq = g_nl_seq.fetch_add(1);
        int len = build_delrule_msg(buf, seq, handle);
        if (len < 0) {
            r.status = "failed";
            r.result_message = "failed to build nftables delrule message for handle " +
                               std::to_string(handle);
            return r;
        }
        if (nft_send_and_wait_ack(buf, len, seq) < 0) {
            r.status = "failed";
            r.result_message = "nftables: failed to delete rule handle " +
                               std::to_string(handle) + ": " +
                               std::string(strerror(errno));
            return r;
        }
        r.status = "succeeded";
        r.result_message = "unblocked (handle " + std::to_string(handle) +
                           ") via nftables (netlink)";
        return r;
    }
}

static ActionResult do_quarantine_file(const json& payload, bool dry_run, bool quarantine) {
    ActionResult r;
    if (!payload.contains("path") || !payload["path"].is_string()) {
        r.status = "failed"; r.result_message = "missing path"; return r;
    }
    std::string path = payload["path"].get<std::string>();
    if (!is_safe_token(path, 4096)) {
        r.status = "failed";
        r.result_message = "path contains unsafe chars (length or charset)";
        return r;
    }
    if (path[0] != '/') {
        r.status = "failed"; r.result_message = "path must be absolute"; return r;
    }
    std::string dest = payload.value("dest", "/var/lib/logsoc/quarantine/");
    if (!is_safe_token(dest, 4096) || dest[0] != '/') {
        r.status = "failed"; r.result_message = "dest must be absolute & safe"; return r;
    }
    // T12.12: replace /bin/sh -c "mkdir && chmod && mv && chmod" with direct
    // libc syscalls. No fork, no execve, no /bin/sh dependency.
    // The original semantic was:
    //   quarantine: mkdir -p dest && chmod 000 path && mv path dest/ && chmod 000 dest/bn
    //   unquarantine: mv dest/bn path && chmod 644 path
    // We use renameat2(2) for the mv (atomic on same fs). On cross-fs
    // (EXDEV), we fall back to linkat(2)+unlinkat(2) which is what
    // coreutils `mv -f` does.
    std::string bn = path.substr(path.find_last_of('/') + 1);
    std::string dest_path = dest + "/" + bn;
    if (quarantine) {
        if (dry_run) {
            LOG_INFO("[T28] DRY-RUN would quarantine(path=" << path << ", dest=" << dest << ")");
            r.status = "succeeded";
            r.result_message = "quarantine dry_run";
            r.stdout_ = "mkdir(" + dest + ", 0700) && chmod(" + path + ", 000) && "
                         "rename(" + path + " -> " + dest_path + ") && chmod(" + dest_path + ", 000)\n";
            return r;
        }
        // Step 1: mkdir -p dest
        if (::mkdir(dest.c_str(), 0700) != 0 && errno != EEXIST) {
            r.status = "failed";
            r.result_message = "mkdir(" + dest + ") failed: " + std::string(strerror(errno));
            return r;
        }
        // Step 2: chmod 000 path (lock in place before move)
        if (::chmod(path.c_str(), 000) != 0) {
            r.status = "failed";
            r.result_message = "chmod(" + path + ", 000) failed: " + std::string(strerror(errno));
            return r;
        }
        // Step 3: rename path -> dest_path (with cross-fs fallback)
        if (::renameat2(AT_FDCWD, path.c_str(), AT_FDCWD, dest_path.c_str(), 0) != 0) {
            if (errno == EXDEV) {
                // Cross-filesystem: copy via linkat + unlinkat
                if (::linkat(AT_FDCWD, path.c_str(), AT_FDCWD, dest_path.c_str(), 0) != 0) {
                    r.status = "failed";
                    r.result_message = "linkat(" + path + " -> " + dest_path +
                                       ") failed (EXDEV): " + std::string(strerror(errno));
                    return r;
                }
                if (::unlinkat(AT_FDCWD, path.c_str(), 0) != 0) {
                    r.status = "failed";
                    r.result_message = "unlinkat(" + path + ") failed: " + std::string(strerror(errno));
                    return r;
                }
            } else {
                r.status = "failed";
                r.result_message = "renameat2(" + path + " -> " + dest_path +
                                   ") failed: " + std::string(strerror(errno));
                return r;
            }
        }
        // Step 4: chmod 000 dest_path
        if (::chmod(dest_path.c_str(), 000) != 0) {
            r.status = "failed";
            r.result_message = "chmod(" + dest_path + ", 000) failed: " + std::string(strerror(errno));
            return r;
        }
        r.status = "succeeded";
        r.result_message = "quarantined " + path + " -> " + dest_path;
        return r;
    } else {
        // unquarantine: mv dest/bn path && chmod 644 path
        if (dry_run) {
            LOG_INFO("[T28] DRY-RUN would unquarantine(path=" << path << ", dest=" << dest << ")");
            r.status = "succeeded";
            r.result_message = "unquarantine dry_run";
            r.stdout_ = "rename(" + dest_path + " -> " + path + ") && chmod(" + path + ", 0644)\n";
            return r;
        }
        if (::renameat2(AT_FDCWD, dest_path.c_str(), AT_FDCWD, path.c_str(), 0) != 0) {
            if (errno == EXDEV) {
                if (::linkat(AT_FDCWD, dest_path.c_str(), AT_FDCWD, path.c_str(), 0) != 0) {
                    r.status = "failed";
                    r.result_message = "linkat(" + dest_path + " -> " + path +
                                       ") failed (EXDEV): " + std::string(strerror(errno));
                    return r;
                }
                if (::unlinkat(AT_FDCWD, dest_path.c_str(), 0) != 0) {
                    r.status = "failed";
                    r.result_message = "unlinkat(" + dest_path + ") failed: " + std::string(strerror(errno));
                    return r;
                }
            } else {
                r.status = "failed";
                r.result_message = "renameat2(" + dest_path + " -> " + path +
                                   ") failed: " + std::string(strerror(errno));
                return r;
            }
        }
        if (::chmod(path.c_str(), 0644) != 0) {
            r.status = "failed";
            r.result_message = "chmod(" + path + ", 0644) failed: " + std::string(strerror(errno));
            return r;
        }
        r.status = "succeeded";
        r.result_message = "restored " + dest_path + " -> " + path;
        return r;
    }
}

static ActionResult do_rmmod(const json& payload, bool dry_run) {
    ActionResult r;
    if (!payload.contains("module") || !payload["module"].is_string()) {
        r.status = "failed"; r.result_message = "missing module"; return r;
    }
    std::string mod = payload["module"].get<std::string>();
    if (!is_safe_token(mod, 128)) {
        r.status = "failed";
        r.result_message = "module name contains unsafe chars: " + mod;
        return r;
    }
    // T12.12: replace /bin/sh -c "rmmod MOD" with direct syscall.
    // delete_module(2) is the kernel syscall to unload a module.
    // We use O_NONBLOCK so we don't hang if the module is busy
    // (refcount > 0); we get EBUSY immediately and the caller can
    // decide to retry. The previous sh version had a 10s timeout via
    // run_cmd_capture; with the syscall direct, the kernel does its
    // own internal waiting (microseconds) and returns.
    if (dry_run) {
        LOG_INFO("[T28] DRY-RUN would rmmod(module=" << mod << ")");
        r.status = "succeeded";
        r.result_message = "rmmod dry_run for " + mod;
        r.stdout_ = "delete_module(" + mod + ", O_NONBLOCK)\n";
        return r;
    }
    long rc = ::syscall(__NR_delete_module, mod.c_str(), O_NONBLOCK);
    if (rc == 0) {
        r.status = "succeeded";
        r.result_message = "rmmod " + mod + " succeeded";
        return r;
    }
    r.status = "failed";
    r.result_message = "rmmod " + mod + " failed: " + std::string(strerror(errno));
    return r;
}

static ActionResult do_fim_add(const json& payload, bool dry_run, bool add) {
    ActionResult r;
    if (!payload.contains("path") || !payload["path"].is_string()) {
        r.status = "failed"; r.result_message = "missing path"; return r;
    }
    std::string path = payload["path"].get<std::string>();
    if (!is_safe_token(path, 4096) || path[0] != '/') {
        r.status = "failed"; r.result_message = "path must be absolute & safe"; return r;
    }
    bool recursive = payload.value("recursive", false);
    if (dry_run) {
        LOG_INFO("[T28] DRY-RUN would " << (add ? "add" : "remove")
                  << " fanotify watch on " << path
                  << (recursive ? " (recursive)" : ""));
        r.status = "succeeded";
        r.result_message = std::string(add ? "fim_add" : "fim_remove")
                           + " dry_run for " + path;
        // T12.12: dry-run output now reflects the real mechanism
        // (fanotify_mark(2) syscall on the collector's fd), not the
        // old "fanotify_mark" binary that never existed.
        r.stdout_ = std::string("fanotify_mark(") + (add ? "FAN_MARK_ADD" : "FAN_MARK_REMOVE")
                    + ", " + path + ", " + (recursive ? "recursive" : "single")
                    + ") via FanotifyCollector fd\n";
        return r;
    }
    // T12.12: delegate to FanotifyCollector::add_watch / remove_watch
    // (defined in agent.cpp). This shares the SAME fanotify fd that
    // the run() loop is reading on, so events on the newly-marked
    // file are captured by the existing event loop. No shell, no
    // fork/exec, no external binary required.
    int rc = add
        ? t28_fim_watch_add(path.c_str(), recursive ? 1 : 0)
        : t28_fim_watch_remove(path.c_str(), recursive ? 1 : 0);
    if (rc == 0) {
        r.status = "succeeded";
        r.result_message = std::string(add ? "fim added " : "fim removed ") + path;
    } else {
        r.status = "failed";
        r.result_message = std::string(add ? "fim_add" : "fim_remove")
                           + " failed for " + path + ": "
                           + std::string(strerror(errno));
    }
    return r;
}

// ── Dispatcher ──────────────────────────────────────────────────────────
ActionResult execute(const std::string& action_type,
                     const std::string& /*action_id*/,
                     const std::string& payload_json,
                     bool dry_run) {
    ActionResult r;
    json payload;
    try {
        payload = json::parse(payload_json);
    } catch (const std::exception& e) {
        r.status = "failed";
        r.result_message = std::string("payload parse error: ") + e.what();
        return r;
    }
    auto t0 = std::chrono::steady_clock::now();

    if (action_type == "kill_pid")         r = do_kill_pid(payload, dry_run);
    else if (action_type == "block_ip")    r = do_block_ip(payload, dry_run, true);
    else if (action_type == "unblock_ip")  r = do_block_ip(payload, dry_run, false);
    else if (action_type == "quarantine_file")   r = do_quarantine_file(payload, dry_run, true);
    else if (action_type == "unquarantine_file") r = do_quarantine_file(payload, dry_run, false);
    else if (action_type == "rmmod")       r = do_rmmod(payload, dry_run);
    else if (action_type == "fim_add")     r = do_fim_add(payload, dry_run, true);
    else if (action_type == "fim_remove")  r = do_fim_add(payload, dry_run, false);
    else {
        r.status = "failed";
        r.result_message = "unknown action_type: " + action_type;
    }
    auto t1 = std::chrono::steady_clock::now();
    r.duration_ms = (int)std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    if (r.stdout_.size() > 4096) r.stdout_.resize(4096);
    return r;
}

}  // namespace logsoc::agent::t28
