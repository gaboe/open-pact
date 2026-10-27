# Control cases

Each JSON file names one registered value. The case runner and coverage test run with `cargo test -p open-pact-client checks::contracts -- --show-output`.

Each case has these fields.

| Field | Meaning |
| --- | --- |
| `name` | Unique case name within one OS and value. |
| `os` | `linux`, `macos`, or `windows`. All platform cases run on every host. The runner derives the adapter from this value and the registered control ID. |
| `input` | Ordered parser inputs. Strings hold fictional command output or file contents. JSON null means an unavailable source. An empty string means a readable empty source. |
| `code` | Command exit code where the selected adapter consumes it. JSON null means no exit status. Parser-only adapters do not consume an exit code. |
| `now` | Fixed UTC observation time. The runner never supplies the host clock to a parser. |
| `expected` | Exact typed result. An integer, a string, and JSON null remain distinct. |
| `observed` | Current parser result when it differs from `expected`. The test asserts this result and reports the difference. |
| `difference` | Public reason for the current parser difference. Required with `observed`. |
| `known_diff` | Public reason the current adapter cannot meet this case. Pair it with `unrepresentable_input` to skip the case. A runnable case with this marker fails: remove it if the case passes, or use `observed` and `difference` for a current difference. |
| `unrepresentable_input` | Evidence the current adapter cannot express. It is valid only with `known_diff`; that case is skipped and does not count as result coverage. |
| `uncovered` | Contract-level list of `{os, result, reason}` entries for table results that have no runnable case because the adapter cannot accept required evidence. A result must be in the documented row and needs a reason. A runnable case makes the entry stale and fails coverage. |

The [adapters](adapters) pass inputs to existing code. They contain no replacement parser. The runner selects one from the case OS and control ID, so a case cannot select another OS's parser. Windows cases enter the registered functions through a thread-local batch fixture and the real batch parser. Linux package cases implement the existing `PackageHost` seam with fictional DNF history and security-query output. Browser cases use the shared policy resolver and aggregation. They do not create a native browser installation.

The ordered inputs follow these conventions.

| OS and value | Inputs |
| --- | --- |
| Windows screen lock | One entry holds all user screen-saver records. Two entries hold machine inactivity policy, then screen-saver records. |
| Windows web protection | SmartScreen policy and local state, then JSON browser records. |
| Other Windows values | One emitted batch field, before the registered check parses it. Skipped cases can describe the missing raw OS evidence instead. |
| Linux firewall | firewalld output, UFW configuration, then UFW service output. |
| Linux screen lock | Three entries hold GNOME enabled state, idle delay, and lock delay. One entry holds KDE configuration. |
| Linux patch age | DNF history output, then cached security update output. |
| Linux automatic updates | Three timer states, raw APT configuration, then raw DNF configuration. Both files pass through the production parsers. |
| Linux account | Current group IDs, then accepted administrative group records. An optional third entry can record an individual sudoers grant that does not change group membership; the current parser does not read that policy. |
| Linux signature age | CVD header bytes as text. |
| Linux preboot | `lsblk` inverse-tree output. The current adapter cannot represent `/proc/cmdline` bytes, crypttab contents, or LUKS metadata. |
| macOS automatic updates | Normally ConfigDataInstall, then CriticalUpdateInstall. Effective OS-install cases provide the raw AutomaticallyInstallMacOSUpdates setting as the first input; the current parser cannot interpret it, so the case records that difference. |
| macOS antimalware | Disabled service output, then XProtect service output. |
| macOS signature age | Installation history, then installed definition version. |
| macOS browser policy | One JSON browser record per discovered member. Null represents an unreadable member. No members represents a complete empty inventory. |
| Other parser cases | Source text from the table in [control contracts](../../../../docs/controls.md). |

Skipped cases hold evidence the current adapter does not accept. They document the intended result without claiming that the current parser can consume that evidence. A skipped case does not count toward result-category coverage. Native policy interpretation and source discovery remain outside these portable tests.

The coverage test compares the registry, the documentation table, and the case files. Each documented result category must have either a runnable case or an `uncovered` entry with a reason. It prints every uncovered entry on each run. A runnable case makes a matching entry stale, so the list only shrinks. A number or timestamp category does not enumerate every possible value. Boundary and negative cases supplement that category coverage.
