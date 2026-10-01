# dsh-kaspersky

A [DSH](https://github.com/deepseek-ai) host plugin that watches Kaspersky and tells
the agent when the antivirus deletes a file the agent just produced.

Real-time protection deletes a build artifact — or a test sample, or a downloaded
binary — seconds after it is written. The agent sees its own file vanish for no
reason it can observe, rebuilds it, and the loop repeats. Kaspersky tells the
harness nothing. This plugin closes that gap:

1. **Listens to Kaspersky.** It reads the `avp.com` detection counter every poll —
   the only signal the product exposes without a password.
2. **Pushes the detection to DSH.** When a file that the agent recently wrote
   disappears, or when the counter rises, the plugin sends the agent a message
   naming every vanished path, what the counter did, and — when credentials are
   configured and the report call succeeded — where the threat report lives.
3. **Warns about the code.** That message states plainly that the code just
   generated may contain malicious content, and tells the agent to inspect the
   source before regenerating anything.

## How it works

Two polls, one message.

```
avp.com STATISTICS File_Monitoring   →  "Total detected: 21 → 22"  ─┐
                                                                    ├─→ followup(agent)
workspace walk (15 s)                →  build.exe disappeared      ─┘
```

* **The counter** comes from `avp.com STATISTICS <profile>`. It needs no login,
  it is monotonic, and a rise between two polls means the antivirus detected
  something. It is read on *every* poll, because the interesting case is a file
  that is written and eaten inside one poll window: the ledger never sees it, and
  the counter is all that is left.
* **The deletion** comes from a ledger: the plugin walks every live session's
  working directory each poll and diffs it against the previous walk. A file
  that was there and is now gone — and was written within the last
  `artifactMaxAgeMs` — is a vanished artifact. Two guards keep that diff honest:
  a root that cannot be listed is forgotten rather than diffed, and a walk that
  hit `maxFiles` or could not open a directory is skipped for that poll, because
  which files fall outside a partial walk moves between polls and would invent
  deletions that never happened.
* **The message** is delivered with `agent.followup(...)`, which wakes the agent.
  It goes to the agents whose working directory contained the vanished file, and
  falls back to the top-level agents when none does — a hand-configured `paths`
  entry can vanish without any session owning it. It is built in the shape
  `createUserMessage()` produces — `{ id, role, content, source }` — with a
  fresh id per alert, because the inbox rejects a splice that would leave two
  pending messages sharing an id.
* **A rise with nothing missing** is delivered too, in its own words: the counter
  proves a detection, not which file it was. That is the write-and-eaten-inside-
  one-poll case, and staying silent about it would miss the timing this plugin
  exists for.
* **Alerts are rate-limited, not dropped.** A deletion inside `minAlertIntervalMs`
  is carried into the next alert, and the counter baseline is left where it was
  until something is actually reported.

### The honesty rule

If the counter did **not** rise, the message says the cause was not measured and
does not name Kaspersky as the deleter. A plugin that cried "the antivirus ate
your file" every time a build script cleaned a directory would be worse than no
plugin at all. The counter is machine-wide, so even a rise is reported as a
detection that coincided with the disappearance, never as proof that these files
are what it deleted. The title changes with the evidence:

| counter | vanished files | title |
| --- | --- | --- |
| rose | yes | 卡巴斯基检出了东西，工作区里有刚生成的产物同时消失 |
| rose | no | 卡巴斯基检出了东西，但本轮没有捕捉到工作区文件消失 |
| unchanged / unreadable | yes | 工作区里有刚生成的产物消失了 |

### What is login-gated

Threat *names* live in `avp.com REPORT <profile> /RA:<file>`, which requires
`/login=` and `/password=` and refuses to write a file without them. Configure
credentials and the alert points at the report; leave them out and the alert
says the names were unavailable. `avp.com` takes no credentials any other way, so
the password is passed on the command line, where any process that can read
command lines on this machine can see it — keep it out of configs you share, or
leave it unset and live without threat names.

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
| `pollMs` | `15000` | Workspace walk and counter interval (floored at 1000 ms). |
| `timeoutMs` | `20000` | Bound on one `avp.com` call. |
| `paths` | `[]` | Extra directories to watch, on top of every session's working directory. A bare string is accepted. |
| `ignore` | `["node_modules", ".git"]` | Directory names the walk never descends into. |
| `maxFiles` | `50000` | Files recorded per workspace per poll. A walk that hits it is skipped, not diffed. |
| `artifactMaxAgeMs` | `7200000` | Only files written within this window count as fresh artifacts. |
| `minAlertIntervalMs` | `30000` | Minimum gap between two pushed alerts; later findings ride along with the next one. |
| `login` / `password` | `''` | `avp.com` credentials, for threat names. Sent on the command line. |

The plugin also adds a short standing section to the system prompt, so an agent
knows the guard exists before it ever trips.

## Verify

```console
$ npm test
```

The suite checks the counter parser against verbatim `avp.com` output, the
ledger against a real temporary tree (including the partial-walk flags), the
message text against every counter outcome — risen, unchanged, reset, unreadable,
and a rise with nothing vanished — and `apply()` against a stand-in Cordis
context: two deleted artifacts delivered as two distinct well-formed messages, a
deletion inside the rate limit carried into the next alert, a vanished workspace
root raising nothing, and a disposed plugin going quiet. The wiring group points
at a nonexistent `avp.com` on purpose, so its timings do not depend on how fast
this machine's antivirus is. The final group is a live probe and is skipped when
`avp.com` is not installed.

Verified end to end on the real machine (Kaspersky 21.26, zh-CN): writing an
EICAR sample into a watched directory, running `avp.com SCAN` on it, and watching
the plugin read `Total detected: 23 → 24`, notice the sample was gone, and push
one `followup` message naming the file, the counter change and the malicious-code
warning into the agent.

Measured on Kaspersky 21.26 (KAVKISKTS, zh-CN) on Windows: `avp.com STATUS` and
`avp.com STATISTICS` work with no login; `avp.com REPORT` and `avp.com TRACES`
print `Login required:` and need credentials. There is no Kaspersky channel in
the Windows Event Log for this product, and `ProgramData\Kaspersky Lab\AVP*\Report\Database\reports.db`
is protected by self-defense, which is why the counter is the signal. One
`avp.com STATISTICS` call costs ~460 ms on this machine, which is what makes
reading it every poll affordable.

## Limits

* Detection is by polling, so a file written and deleted inside one poll window is
  invisible to the ledger — the counter rise is what reports it, and that message
  cannot name the file. `fs.watch` would miss events under load; a walk is
  deterministic.
* The counter is machine-wide. A detection anywhere on the machine — a user scan,
  another folder, a download — raises it, so an alert can name a file that
  Kaspersky did not delete and a deletion it did not cause.
* Alerts list everything that vanished since the last alert, and one text goes to
  every affected agent. With sessions in different directories, an agent can be
  told about a file outside its own workspace.
* The ledger records paths, sizes and mtimes only — never file contents.
* Without credentials, an alert can say *that* something was detected but not
  *what*.
* Only Windows, only `avp.com`. Other products have their own counters.
* The plugin cannot install itself: the `desktop` profile of this harness is
  managed by the Electron app, and its `cordis.patch.yml` is not meant to be
  hand-edited. Install it with the plugin manager (`install_bundle`).

## License

MIT
