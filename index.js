/**
 * dsh-kaspersky — watch Kaspersky, and tell the agent when it eats its work.
 *
 * The problem this solves is concrete: real-time protection deletes a build
 * artifact (or a test sample) seconds after the agent writes it. The agent
 * sees its own file vanish for no reason it can observe, rebuilds, and the
 * cycle repeats. Kaspersky does not tell the harness anything.
 *
 * So this plugin does three things, and nothing else:
 *
 * 1. **Watches Kaspersky.** It polls `avp.com STATISTICS <profile>` for the
 *    `Total detected:` counter — the only signal the product exposes without a
 *    password.
 * 2. **Watches the workspace.** It keeps a ledger of files under every live
 *    session's working directory and detects files that disappear.
 * 3. **Tells the agent.** When a recently written file vanishes, it pushes one
 *    message into the agents that own that directory: which files are gone,
 *    what the counter did, and the warning that the code just generated may
 *    contain malicious content.
 *
 * When files vanish but the counter did not rise, the message says the cause
 * was not measured. The plugin never asserts Kaspersky deleted something it
 * did not see Kaspersky detect.
 *
 * @module dsh-kaspersky
 */

import { randomUUID } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join, resolve, sep } from 'node:path'

import { findAvp, readTotalDetected, writeThreatReport } from './lib/kaspersky.js'
import { DEFAULT_IGNORE, diff, isReadableDir, scan } from './lib/ledger.js'
import { buildAlert, buildPromptSection } from './lib/messages.js'

/** Required services; the plugin stays inactive in a profile without them. */
export const inject = ['agents', 'systemPrompt']

/** Everything a user can tune from `cordis.patch.yml`. */
const DEFAULTS = {
	/** avp.com command. Empty means: look in the known Kaspersky install dirs. */
	avp: '',
	/** Which protection component's counter to read. */
	statisticsProfile: 'File_Monitoring',
	/** How often to walk the workspaces, in milliseconds. */
	pollMs: 15_000,
	/** Bound on a single avp.com call, in milliseconds. */
	timeoutMs: 20_000,
	/** How often the counter baseline is refreshed while nothing disappears. */
	counterRefreshMs: 300_000,
	/** Extra directories to watch, absolute or relative to the host's cwd. */
	paths: [],
	/** Directory names the ledger walk never descends into. */
	ignore: DEFAULT_IGNORE,
	/** Upper bound on files recorded per workspace, per poll. */
	maxFiles: 50_000,
	/** Only files touched within this window count as fresh artifacts. */
	artifactMaxAgeMs: 2 * 60 * 60 * 1000,
	/** Minimum gap between two pushed alerts, in milliseconds. */
	minAlertIntervalMs: 30_000,
	/** avp.com credentials; without them threat names stay unavailable. */
	login: '',
	password: '',
}

/** Section order 3200: after the tool sections, before the SDK ones. */
const SECTION_ORDER = 3200

/** Whether `child` is `parent` itself or sits underneath it. */
function contains(parent, child) {
	if (parent === child) return true
	const withSep = parent.endsWith(sep) ? parent : parent + sep
	return child.startsWith(withSep)
}

/**
 * One inbox message, in the shape `createUserMessage()` from
 * `@deepseek-ai/dsh-llm` builds: `{ id, role, content, source }`, frozen.
 *
 * The id is not decoration. The agent inbox rejects a splice that would leave
 * two pending messages sharing an id, and a message without one collides with
 * itself — so a second alert while the first is still queued would be thrown
 * away. Rebuilt here rather than imported to keep the bundle dependency-free.
 */
function buildMessage(text) {
	return Object.freeze({
		id: randomUUID(),
		role: 'user',
		content: Object.freeze([Object.freeze({ type: 'text', text })]),
		source: Object.freeze({ kind: 'plugin', plugin: 'dsh-kaspersky' }),
	})
}

export function apply(ctx, config) {
	const options = { ...DEFAULTS, ...(config ?? {}) }
	const paths = options.paths.map((path) => resolve(path))
	// `logger` is a core context property rather than an injected service, but
	// the shipped user plugins still guard it: a missing logger must not be
	// what stops the watcher from loading.
	const logger = ctx.logger ?? console

	/** root → (path → { size, mtimeMs }) from the previous poll. */
	const ledgers = new Map()
	/** Last counter value seen, or null before the first successful read. */
	let lastTotal = null
	let lastTotalAt = 0
	let lastAlertAt = 0
	/** Resolved once; re-resolved while null so an install after boot is picked up. */
	let avp = findAvp(options.avp)

	logger.info(
		`dsh-kaspersky: watching every session workspace every ${Math.round(options.pollMs / 1000)}s`
			+ (avp ? `, avp.com at ${avp}` : ', avp.com not found yet'),
	)

	ctx.systemPrompt.section({
		name: 'dsh-kaspersky:guard',
		order: SECTION_ORDER,
		text: buildPromptSection({
			pollMs: options.pollMs,
			profile: options.statisticsProfile,
			paths,
		}),
	})

	/** Working directories of every live agent, plus the configured extras. */
	function watchRoots() {
		const roots = new Set(paths)
		for (const agent of ctx.agents.list()) {
			try {
				const cwd = agent?.session?.header?.cwd
				if (typeof cwd === 'string' && cwd.length > 0) roots.add(resolve(cwd))
			} catch {
				// A disposing agent is not this poll's problem.
			}
		}
		return [...roots]
	}

	/** The agents whose working directory contains one of the vanished files. */
	function pickTargets(vanished, roots) {
		const touched = new Set(vanished.map((file) => file.path))
		const owners = []
		for (const agent of ctx.agents.list()) {
			let cwd
			try {
				cwd = agent?.session?.header?.cwd
			} catch {
				continue
			}
			if (typeof cwd !== 'string' || cwd.length === 0) continue
			const root = resolve(cwd)
			if (!roots.includes(root)) continue
			for (const path of touched) {
				if (contains(root, path)) {
					owners.push(agent)
					break
				}
			}
		}
		return owners.length > 0 ? owners : ctx.agents.roots()
	}

	/** Read the counter, remembering what a failure looked like for the alert. */
	async function readCounter() {
		avp ??= findAvp(options.avp)
		const result = await readTotalDetected(avp, options.statisticsProfile, options.timeoutMs)
		if (typeof result.total === 'number') lastTotalAt = Date.now()
		return result
	}

	async function tick() {
		const roots = watchRoots()
		if (roots.length === 0) return // no live session yet; nothing to remember

		const vanished = []
		for (const root of roots) {
			const current = await scan(root, { ignore: options.ignore, maxFiles: options.maxFiles })
			const previous = ledgers.get(root)
			// An unreadable root walks as empty, and diffing that would report the
			// whole workspace as deleted. Forget the baseline instead, so the next
			// readable poll re-establishes it.
			if (current.size === 0 && !(await isReadableDir(root))) {
				ledgers.delete(root)
				continue
			}
			ledgers.set(root, current)
			if (previous === undefined) continue // first poll only establishes the ledger
			vanished.push(...diff(previous, current, { maxAgeMs: options.artifactMaxAgeMs }))
		}
		// Sessions end; their ledgers must not outlive them.
		for (const root of ledgers.keys()) if (!roots.includes(root)) ledgers.delete(root)
		if (vanished.length === 0) {
			// Refresh the baseline occasionally so a later rise stays attributable,
			// without paying for an avp.com process on every single poll.
			if (Date.now() - lastTotalAt > options.counterRefreshMs) {
				const before = lastTotal
				const read = await readCounter()
				if (typeof read.total === 'number') lastTotal = read.total
				// A detection the workspace never felt. Worth saying out loud in the
				// harness log, never worth waking an agent for.
				if (before !== null && typeof read.total === 'number' && read.total > before) {
					logger.warn(
						`dsh-kaspersky: ${options.statisticsProfile} detected ${read.total - before} more object(s)`
							+ ` (counter ${before} → ${read.total}) but no watched file disappeared`,
					)
				}
			}
			return
		}

		const read = await readCounter()
		const counter = {
			before: lastTotal,
			after: typeof read.total === 'number' ? read.total : null,
			profile: options.statisticsProfile,
		}
		if (typeof read.total === 'number') lastTotal = read.total

		if (Date.now() - lastAlertAt < options.minAlertIntervalMs) return
		lastAlertAt = Date.now()

		let threat = { problem: read.problem ?? '未配置 avp.com 登录名/密码' }
		if (options.login && options.password) {
			threat = await writeThreatReport(avp, {
				profile: options.statisticsProfile,
				login: options.login,
				password: options.password,
				outFile: join(tmpdir(), `dsh-kaspersky-report-${Date.now()}.txt`),
				timeoutMs: options.timeoutMs,
				all: true,
			})
		}

		const text = buildAlert({ vanished, roots, counter, threat })
		for (const agent of pickTargets(vanished, roots)) {
			try {
				agent.followup(buildMessage(text))
			} catch (error) {
				logger.warn(`dsh-kaspersky: could not reach agent "${agent?.id}": ${String(error)}`)
			}
		}
	}

	/** Never let one bad poll kill the timer. */
	const safely = () => {
		tick().catch((error) => logger.warn(`dsh-kaspersky: poll failed: ${String(error)}`))
	}
	safely()
	const timer = setInterval(safely, options.pollMs)
	timer.unref?.()

	return ctx.effect(() => () => clearInterval(timer))
}
