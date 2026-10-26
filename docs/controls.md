# Client controls

The client reports the controls in this table only when the signed manifest lists them.

| Control | Result | Device data | Limit |
| --- | --- | --- | --- |
| `managed_repos_outside` | Integer count | Matching repositories outside every `[managed_repos].folders` entry | A repository must have a remote that matches a signed pattern. A copy without a remote is not counted. |
| `managed_repos_total` | Integer count | All matching repositories | A repository must have a remote that matches a signed pattern. |

The client scans the user's home at `join`, `check`, and at most once per 24 hours during a scheduled run. The scan walks to depth 8 and does not follow symlinks. It skips `node_modules`, `target`, `bin`, `obj`, `.Trash`, and `~/Library`. A scan result becomes `unknown` when it is older than 48 hours.

The client reads remote URLs from each repository's local Git configuration. It does not run Git. It counts SSH, HTTPS, and scp-style URLs when their host and path match a pattern in the signed manifest. An exact SSH `Host` alias can map to a `HostName` in `~/.ssh/config`.

The device stores the scan time, counts, and outside paths in `repo-scan.json` in the client home. Only the two integer counts enter a report. The client prints outside paths locally so the owner can move each repository into a registered folder.

This scan cannot find a copy without a matching remote. A `url.*.insteadOf` rewrite in `~/.gitconfig` can hide a matching remote. A repository deeper than eight levels can be missed. The scanner ignores SSH wildcard host entries and does not read SSH `Include` files. An unreadable directory stops the scan instead of producing a partial count.
