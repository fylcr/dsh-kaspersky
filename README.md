# dsh-kaspersky

A [DSH](https://github.com/deepseek-ai) host plugin that watches Kaspersky and tells
the agent when the antivirus deletes a file the agent just produced.

Real-time protection deletes a build artifact — or a test sample, or a downloaded
binary — seconds after it is written. The agent sees its own file vanish for no
reason it can observe, rebuilds it, and the loop repeats. Kaspersky tells the
harness nothing. This plugin closes that gap:

1. **Listens to Kaspersky.** It polls `avp.com` for the antivirus detection
   counter — the only signal the product exposes without a password.
2. **Pushes the detection to DSH.** When a file that the agent recently wrote
   disappears, the plugin sends the agent a message naming every vanished path,
   what the counter did, and where the threat report lives.
3. **Warns about the code.** That message states plainly that the code just
   generated may contain malicious content, and tells the agent to inspect the
   source before regenerating anything.

## How it works

Two polls, one message.

```
avp.com STATISTICS File_Monitoring   →  "Total detected: 21"   ─┐
                                                                 ├─→ followup(agent)
workspace walk (15 s)                →  build.exe disappeared  ─┘
```

* **The counter** comes from `avp.com STATISTICS <profile>`. It needs no login,
  it is monotonic, and a rise between two polls means the antivirus detected
  something.
* **The deletion** comes from a ledger: the plugin walks every live session's
  working directory each poll and diffs it against the previous walk. A file
  that was there and is now gone — and was written within the last
  `artifactMaxAgeMs` — is a vanished artifact. A root that cannot be listed is
  forgotten rather than diffed, so an unreadable workspace never reads as a
  deleted one.
* **The message** is delivered with `agent.followup(...)`, which wakes the agent.
  It goes to the agents whose working directory contained the vanished file, and
  falls back to the top-level agents when none does — a hand-configured `paths`
  entry can vanish without any session owning it. It is built in the shape
  `createUserMessage()` produces — `{ id, role, content, source }` — with a
  fresh id per alert, because the inbox rejects a splice that would leave two
  pending messages sharing an id.
* **Detections that cannot be localised** are logged, not delivered. If the
  counter rises across a baseline refresh while no watched file disappeared, the
  plugin writes one line to the harness log. The detection may have been blocked
  rather than deleted, or may not have been in a workspace at all; waking an
  agent for that would be noise.

### The honesty rule

If the counter did **not** rise, the message says the cause was not measured and
does not name Kaspersky as the deleter. A plugin that cried "the antivirus ate
your file" every time a build script cleaned a directory would be worse than no
plugin at all. The alert title changes with the evidence:

| counter | title |
| --- | --- |
| rose | 卡巴斯基删除了刚生成的产物 |
| unchanged | 工作区里有刚生成的产物消失了 |

### What is login-gated

Threat *names* live in `avp.com REPORT <profile> /RA:<file>`, which requires
`/login=` and `/password=` and refuses to write a file without them. Configure
credentials and the alert points at the report; leave them out and the alert
says the names were unavailable.

## Install

Install the bundle with the plugin manager (`install_bundle`, absolute path to
this directory), or add it as a profile bundle. The manifest is standard:

```yaml
# cordis.patch.yml
- insert:
    - id: kaspersky-guard
      name: dsh-kaspersky
      config: {}
```

Every key is optional. A profile-level override of this row **replaces** the
whole `config` object, so copy the keys you want to keep.

| key | default | meaning |
| --- | --- | --- |
| `avp` | `''` | `avp.com` to run. Empty auto-detects under `C:\Program Files*\Kaspersky Lab\Kaspersky *\`. |
| `statisticsProfile` | `File_Monitoring` | Protection component whose counter is watched. |
| `pollMs` | `15000` | Workspace walk interval. |
| `timeoutMs` | `20000` | Bound on one `avp.com` call. |
| `counterRefreshMs` | `300000` | How often the counter baseline is refreshed while nothing disappears. |
| `paths` | `[]` | Extra directories to watch, on top of every session's working directory. |
| `ignore` | `["node_modules", ".git"]` | Directory names the walk never descends into. |
| `maxFiles` | `50000` | Files recorded per workspace per poll. |
| `artifactMaxAgeMs` | `7200000` | Only files written within this window count as fresh artifacts. |
| `minAlertIntervalMs` | `30000` | Minimum gap between two pushed alerts. |
| `login` / `password` | `''` | `avp.com` credentials, for threat names. |

The plugin also adds a short standing section to the system prompt, so an agent
knows the guard exists before it ever trips.

## Verify

```console
$ npm test
```

The suite checks the counter parser against verbatim `avp.com` output, the
ledger against a real temporary tree, the message text against both counter
outcomes, and `apply()` against a stand-in Cordis context — including that two
deleted artifacts are delivered as two distinct, well-formed messages. The
final group is a live probe and is skipped when `avp.com` is not installed.

Measured on Kaspersky 21.26 (KAVKISKTS, zh-CN) on Windows: `avp.com STATUS` and
`avp.com STATISTICS` work with no login; `avp.com REPORT` and `avp.com TRACES`
print `Login required:` and need credentials. There is no Kaspersky channel in
the Windows Event Log for this product, and `ProgramData\Kaspersky Lab\AVP*\Report\Database\reports.db`
is protected by self-defense, which is why the counter is the signal.

## Limits

* Detection is by polling, so a file deleted and recreated between two walks is
  invisible. `fs.watch` would miss events under load; a walk is deterministic.
* The ledger records paths, sizes and mtimes only — never file contents.
* Without credentials, an alert can say *that* something was detected but not
  *what*.
* Only Windows, only `avp.com`. Other products have their own counters.

## License

MIT
