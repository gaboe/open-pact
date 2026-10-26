# Control cases

Each JSON file names one registered value. The case runner and coverage test run with `cargo test -p open-pact-client checks::contracts -- --show-output`.

Each case has these fields.

| Field | Meaning |
| --- | --- |
| `name` | Unique case name within one OS and value. |
| `os` | `linux`, `macos`, or `windows`. All platform cases run on every host. |
| `seam` | Existing parser or collector seam, selected by the test adapter. `registry` calls a registered platform constant. |
| `input` | Ordered parser inputs. Strings hold fictional command output or file contents. JSON null means an unavailable source. An empty string means a readable empty source. |
| `code` | Command exit code where the seam consumes it. JSON null means no exit status. Parser-only seams do not consume an exit code. |
| `now` | Fixed UTC observation time. The runner never supplies the host clock to a parser. |
| `expected` | Exact typed result. An integer, a string, and JSON null remain distinct. |
| `known_diff` | Reason and study reference for an unimplemented contract. `pending integration` identifies the two pending branches. JSON null means the case must pass. |

The [adapters](adapters) pass inputs to existing code. They contain no replacement parser. Windows cases enter the registered functions through a thread-local batch fixture and the real batch parser. Linux package cases implement the existing `PackageHost` seam with fictional DNF history and security-query output. Browser cases use the shared policy resolver and aggregation. They do not create a native browser installation.

The ordered inputs follow these conventions.

| Seam and value | Inputs |
| --- | --- |
| Windows screen lock | One entry holds all user screen-saver records. Two entries hold machine inactivity policy, then screen-saver records. |
| Windows web protection | SmartScreen policy and local state, then JSON browser records. |
| Other Windows values | One emitted batch field, before the registered check parses it. Skipped cases can describe the missing raw OS evidence instead. |
| Linux firewall | firewalld output, UFW configuration, then UFW service output. |
| Linux screen lock | Three entries hold GNOME enabled state, idle delay, and lock delay. One entry holds KDE configuration. |
| Linux patch age | DNF history output, then cached security update output. |
| Linux automatic updates | Effective timer states with the installation action. |
| Linux account | Current group IDs, then accepted administrative group records. |
| Linux signature age | CVD header bytes as text. |
| Pending Linux preboot | JSON inverse block tree, kernel command line, crypttab contents, then LUKS metadata when applicable. |
| macOS automatic updates | ConfigDataInstall, then CriticalUpdateInstall. |
| macOS antimalware | Disabled service output, then XProtect service output. |
| macOS signature age | Installation history, then installed definition version. |
| macOS browser policy | One JSON browser record per discovered member. Null represents an unreadable member. No members represents a complete empty inventory. |
| Other parser cases | Source text from the table in [control contracts](../../../../docs/controls.md). |

Skipped cases can hold extra evidence that the current collector does not read. They document the intended result without claiming that the current parser can consume that evidence. Native policy interpretation and source discovery remain outside these portable tests.

The coverage test compares the registry, the documentation table, and the case files. Each documented result category must have a case on its OS. A number or timestamp category does not enumerate every possible value. Boundary and negative cases supplement that category coverage.
