- 👋 Hi, I’m Hubert.
- 👀 find out more about me here: https://hubdamian95.github.io/

## Upstream Linux NFS contributions

Fixes in the Linux NFS client stack that I diagnosed and worked on with the VAST Data team, who submitted them upstream to the `linux-nfs` mailing list.

| Project | Fix | Status |
|---|---|---|
| Linux kernel (`sunrpc`) | [Don't dereference a destroyed credcache from the cred shrinker](https://lore.kernel.org/all/20261125180751.3804694-1-dan.aloni@vastdata.com/): fixes a kernel oops in `kswapd` when the cred shrinker races `rpcauth_destroy_credcache()` | Submitted, under review |
| nfs-utils (`gssd`) | [Check the machine ccache's TGT instead of a cached endtime](https://lore.kernel.org/all/20261125182211.3830485-1-dan.aloni@vastdata.com/): stops gssd reporting valid credentials after an external writer replaces an expired ticket cache | Submitted, under review |
| Linux kernel (`sunrpc`) | [Fix missing initialization of GSS `au_flags`](https://lore.kernel.org/all/20261124130027.1432127-1-dan.aloni@vastdata.com/): uninitialized slab data made RPC/RDMA pick a reply chunk instead of a write chunk for large READs | Submitted, under review |

<!-- When a patch is merged, replace its status with a link to the commit. -->

<!---
HubDamian95/HubDamian95 is a ✨ special ✨ repository because its `README.md` (this file) appears on your GitHub profile.
You can click the Preview link to take a look at your changes.
--->
