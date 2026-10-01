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
 *    password. The counter is read every poll, because a file can be written
 *    and eaten well inside one poll window, and then the ledger below never
 *    sees it at all.
 * 2. **Watches the workspace.** It keeps a ledger of files under every live
 *    session's working directory and detects files that disappear.
 * 3. **Tells the agent.** When a recently written file vanishes — or when the
 *    counter rises without one doing so — it pushes one message into the
 *    agents that own that directory: which files are gone, what the counter
 *    did, and the warning that the code just generated may contain malicious
 *    content.
 *
 * The message names Kaspersky as the cause only as far as it measured it: the
 * counter is machine-wide, so a rise is reported as a detection that coincided
 * with the disappearance, never as proof that these files were what it deleted.
 * When the counter did not rise, the message says the cause was not measured.
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
	/** How often to walk the workspaces and read the counter, in milliseconds. */
	pollMs: 15_000,
	/** Bound on a single avp.com call, in milliseconds. */
	timeoutMs: 20_000,
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
	/** avp.com credentials, for threat names. Passed on the command line. */
	login: '',
	password: '',
}

/** Section order 3200: after the tool sections, before the SDK ones. */
const SECTION_ORDER = 3200

/** Windows compares paths case-insensitively, so the plugin must too. */
const foldCase = (path) => (process.platform === 'win32' ? path.toLowerCase() : path)

/** Whether `child` is `parent` itself or sits underneath it. Both folded. */
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

/** A config value that should be an array of strings, from YAML or defaults. */
function stringList(value, fallback) {
	if (Array.isArray(value)) return value.filter((item) => typeof item === 'string' && item.length > 0)
	if (typeof value === 'string' && value.length > 0) return [value] // `paths: D:\work`
	return fallback
}

/** A config value that should be a number, clamped so a typo cannot spin a poll. */
function number(value, fallback, min) {
	const parsed = Number(value)
	return Number.isFinite(parsed) ? Math.max(min, parsed) : fallback
}

export function apply(ctx, config) {
	const options = { ...DEFAULTS, ...(config ?? {}) }
	const paths = stringList(options.paths, []).map((path) => resolve(path))
	const ignore = stringList(options.ignore, DEFAULT_IGNORE)
	const pollMs = number(options.pollMs, DEFAULTS.pollMs, 1000)
	const maxFiles = number(options.maxFiles, DEFAULTS.maxFiles, 1)
	const minAlertIntervalMs = number(options.minAlertIntervalMs, DEFAULTS.minAlertIntervalMs, 0)
	// `logger` is a core context property rather than an injected service, but
	// the shipped user plugins still guard it: a missing logger must not be
	// what stops the watcher from loading.
	const logger = ctx.logger ?? console

	/** folded root → (path → { size, mtimeMs }) from the previous poll. */
	const ledgers = new Map()
	/** Vanished files held back by the alert rate limit, reported next time. */
	let pending = []
	/** Last counter value seen, or null before the first successful read. */
	let lastTotal = null
	let lastAlertAt = 0
	/** Roots already reported as unreadable, so the warning is said once. */
	const complained = new Set()
	/** A poll that is still running must not be joined by the next one. */
	let running = false
	let disposed = false
	/** Resolved once; re-resolved while null so an install after boot is picked up. */
	let avp = findAvp(options.avp)

	logger.info(
		`dsh-kaspersky: watching every session workspace every ${Math.round(pollMs / 1000)}s`
			+ (avp ? `, avp.com at ${avp}` : ', avp.com not found yet'),
	)

	ctx.systemPrompt.section({
		name: 'dsh-kaspersky:guard',
		order: SECTION_ORDER,
		text: buildPromptSection({
			pollMs,
			profile: options.statisticsProfile,
			paths,
		}),
	})

	/** Working directories of every live agent, plus the configured extras. */
	function watchRoots() {
		const roots = new Map()
		for (const path of paths) roots.set(foldCase(path), path)
		for (const agent of ctx.agents.list()) {
			try {
				const cwd = agent?.session?.header?.cwd
				if (typeof cwd !== 'string' || cwd.length === 0) continue
				const resolved = resolve(cwd)
				const key = foldCase(resolved)
				if (!roots.has(key)) roots.set(key, resolved)
			} catch {
				// A disposing agent is not this poll's problem.
			}
		}
		return roots
	}

	/** The agents whose working directory contains one of the vanished files. */
	function pickTargets(vanished, roots) {
		const touched = vanished.map((file) => foldCase(file.path))
		const owners = []
		for (const agent of ctx.agents.list()) {
			let cwd
			try {
				cwd = agent?.session?.header?.cwd
			} catch {
				continue
			}
			if (typeof cwd !== 'string' || cwd.length === 0) continue
			const key = foldCase(resolve(cwd))
			if (!roots.has(key)) continue
			if (touched.some((path) => contains(key, path))) owners.push(agent)
		}
		if (owners.length > 0) return owners
		// A hand-configured path can vanish without any session owning it.
		try {
			return ctx.agents.roots()
		} catch (error) {
			logger.warn(`dsh-kaspersky: could not list root agents: ${String(error)}`)
			return []
		}
	}

	/** Say a thing about one root once, however many polls it stays true. */
	function complainOnce(key, message) {
		if (complained.has(key)) return
		complained.add(key)
		logger.warn(`dsh-kaspersky: ${message}`)
	}

	/** Read the counter; never throws, and reports why when it fails. */
	async function readCounter() {
		avp ??= findAvp(options.avp)
		return readTotalDetected(avp, options.statisticsProfile, options.timeoutMs)
	}

	async function tick() {
		if (disposed) return

		const roots = watchRoots()
		if (roots.size === 0) return // no live session yet; nothing to remember

		const vanished = [...pending]
		for (const [key, root] of roots) {
			const current = await scan(root, { ignore, maxFiles })
			const previous = ledgers.get(key)
			// An unreadable root walks as empty, and diffing that would report the
			// whole workspace as deleted. Forget the baseline instead, so the next
			// readable poll re-establishes it.
			if (current.size === 0 && !(await isReadableDir(root))) {
				ledgers.delete(key)
				complainOnce(key, `watch root ${root} cannot be listed; its baseline was dropped`)
				continue
			}
			ledgers.set(key, current)
			if (previous === undefined) continue // first poll only establishes the ledger
			// A walk that hit the file cap, or could not open a directory, is a
			// partial view: which files fell outside it moves between polls, and
			// diffing it would invent deletions that never happened.
			if (current.truncated || current.unreadable || previous.truncated || previous.unreadable) {
				complainOnce(
					key,
					`walk of ${root} was incomplete (${current.truncated || previous.truncated ? 'hit maxFiles' : 'unreadable directory'});`
						+ ' no deletions were reported for it this poll',
				)
				continue
			}
			vanished.push(...diff(previous, current, { maxAgeMs: options.artifactMaxAgeMs }))
		}
		// Sessions end; their ledgers must not outlive them.
		for (const key of ledgers.keys()) if (!roots.has(key)) ledgers.delete(key)

		// Read the counter every poll: a file written and eaten inside one poll
		// window never reaches the ledger, and the counter is all that is left.
		const read = await readCounter()
		const before = lastTotal
		const after = typeof read.total === 'number' ? read.total : null
		const rose = before !== null && after !== null && after > before
		const counter = { before, after, profile: options.statisticsProfile, problem: read.problem }

		if (vanished.length === 0 && !rose) {
			pending = []
			if (after !== null) lastTotal = after // quiet poll: keep the baseline current
			return
		}

		if (Date.now() - lastAlertAt < minAlertIntervalMs) {
			// Held back, not dropped: the baseline is left where it was and the
			// files are carried into the next alert, so the rise is still reported.
			pending = vanished
			return
		}

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

		const text = buildAlert({ vanished, roots: [...roots.values()], counter, threat })
		pending = []
		if (after !== null) lastTotal = after
		lastAlertAt = Date.now()

		for (const agent of pickTargets(vanished, roots)) {
			try {
				agent.followup(buildMessage(text))
			} catch (error) {
				logger.warn(`dsh-kaspersky: could not reach agent "${agent?.id}": ${String(error)}`)
			}
		}
	}

	/** Never let one bad poll kill the timer, and never run two at once. */
	const safely = async () => {
		if (running || disposed) return
		running = true
		try {
			await tick()
		} catch (error) {
			logger.warn(`dsh-kaspersky: poll failed: ${String(error)}`)
		} finally {
			running = false
		}
	}
	void safely()
	const timer = setInterval(() => void safely(), pollMs)
	timer.unref?.()

	return ctx.effect(() => () => {
		disposed = true
		clearInterval(timer)
	})
}
