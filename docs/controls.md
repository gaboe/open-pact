# Client controls

The client reports the controls in this table only when the signed manifest lists them.

| Control | Result | Device data | Limit |
| --- | --- | --- | --- |
| `managed_repos_outside` | Integer count | Matching repositories outside every `[managed_repos].folders` entry | A repository must have a remote that matches a signed pattern. A copy without a remote is not counted. |
| `managed_repos_total` | Integer count | All matching repositories | A repository must have a remote that matches a signed pattern. |
| Either repository control when no scan exists or the scan is older than 48 hours | `unknown` | No current scan result | The scheduled scan runs at most once per 24 hours from the last scan attempt, including a partial scan. |
| Either repository control when `repo-scan.json` is corrupt | `unknown` | No usable stored scan | The report continues and sends the other controls. |
| Either repository control after a partial scan | `unknown` | The scan could not read one or more folders | The local scan file keeps the attempt time, partial flag, access status, and paths found. The report sends no partial counts because an unreadable folder could hide a matching repository. |
| Either repository control after macOS denies folder access | `unknown` | Some folders could not be read | Grant Full Disk Access to the client binary. `check` prints the binary path and does not print denied folder paths. |

The client scans the user's home at `join`, `check`, and at most once per 24 hours during a scheduled run. A scheduled scan waits 24 hours after every attempt, including a partial scan. The scan walks to depth 8 and does not follow symlinks. It skips `node_modules`, `target`, `bin`, `obj`, `.Trash`, and `~/Library`. A scan result becomes `unknown` when it is older than 48 hours.

The client reads remote URLs from each repository's local Git configuration. It does not run Git. It counts SSH, HTTPS, and scp-style URLs when their host and path match a pattern in the signed manifest. SSH aliases use the first `HostName` from matching `Host` blocks in file order, including wildcard and negated patterns.

The device stores the scan time, counts, and outside paths in `repo-scan.json` in the client home. Only the two integer counts enter a report. The client prints outside paths locally so the owner can move each repository into a registered folder.

This scan cannot find a copy without a matching remote. A `url.*.insteadOf` rewrite in `~/.gitconfig` can hide a matching remote. A repository deeper than eight levels can be missed. The scanner does not read SSH `Include` files. An unreadable folder makes both repository counts `unknown`; the scan continues and records its partial status locally.
