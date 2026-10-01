/**
 * `npm test` — one runnable check for every claim the README makes.
 *
 * The first four groups are pure and always run. The last group is a live
 * probe: it runs only if avp.com is actually installed, so the suite stays
 * green on a machine without Kaspersky.
 *
 * The wiring group points the plugin at a nonexistent avp.com on purpose: the
 * counter then fails to read instantly instead of spawning a real scanner, so
 * the timings below do not depend on how fast this machine's antivirus is.
 */

import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { apply } from '../index.js'
import { findAvp, parseTotalDetected, readTotalDetected } from '../lib/kaspersky.js'
import { diff, isReadableDir, scan } from '../lib/ledger.js'
import { buildAlert, buildPromptSection } from '../lib/messages.js'

let passed = 0
let failed = 0

function check(label, condition, detail) {
	if (condition) {
		passed += 1
		console.log(`  ok   ${label}`)
	} else {
		failed += 1
		console.error(`  FAIL ${label}${detail === undefined ? '' : ` — ${detail}`}`)
	}
}

/** A throwaway directory that is removed once `body` settles. */
async function withTempDir(body) {
	const dir = mkdtempSync(join(tmpdir(), 'dsh-kaspersky-test-'))
	try {
		return await body(dir)
	} finally {
		rmSync(dir, { recursive: true, force: true })
	}
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

/** Wait for a condition instead of guessing how long the machine needs. */
async function waitFor(condition, timeoutMs, stepMs = 50) {
	const deadline = Date.now() + timeoutMs
	while (Date.now() < deadline) {
		if (condition()) return true
		await sleep(stepMs)
	}
	return condition()
}

console.log('parseTotalDetected')

// Verbatim excerpt of `avp.com STATISTICS File_Monitoring` on a real install.
const statistics = [
	'Time Start: 2026-09-27 18:47:09',
	'Total detected: 21',
	'Suspicions: 62',
	'Processed objects: 4733916',
].join('\r\n')
check('reads the counter from live STATISTICS output', parseTotalDetected(statistics) === 21)

// Verbatim excerpt of the statistics footer of an `avp.com SCAN /R:` report.
const report = [';  --- Statistics ---', '; Time Start: 2026-10-01 10:28:13', '; Total detected: 0'].join('\n')
check('reads the counter from a scan report', parseTotalDetected(report) === 0)
check('returns null when the counter is absent', parseTotalDetected('Access denied') === null)

console.log('ledger')

await withTempDir(async (dir) => {
	mkdirSync(join(dir, 'src'))
	mkdirSync(join(dir, 'node_modules'))
	writeFileSync(join(dir, 'src', 'build.exe'), 'binary')
	writeFileSync(join(dir, 'node_modules', 'dep.js'), 'ignored')

	const before = await scan(dir)
	check('records nested files', before.has(join(dir, 'src', 'build.exe')))
	check('skips ignored directories', ![...before.keys()].some((path) => path.includes('node_modules')))
	check('a complete walk is not flagged as partial', before.truncated === false && before.unreadable === false)

	rmSync(join(dir, 'src', 'build.exe'))
	const after = await scan(dir)
	const vanished = diff(before, after, { maxAgeMs: 60_000 })
	check('reports the deleted file', vanished.length === 1 && vanished[0].path.endsWith('build.exe'))

	const aged = diff(before, after, { now: Date.now() + 3_600_000, maxAgeMs: 60_000 })
	check('ignores deletions older than artifactMaxAgeMs', aged.length === 0)

	// A file that appears must never be reported as having vanished.
	writeFileSync(join(dir, 'src', 'later.exe'), 'new')
	check('never reports new files as vanished', diff(after, await scan(dir), { maxAgeMs: 60_000 }).length === 0)

	check('a missing root scans as empty rather than throwing', (await scan(join(dir, 'nope'))).size === 0)

	// "Empty" and "unreadable" walk identically, and only one of them means the
	// workspace is gone — this is what stops a vanished root from being reported
	// as a workspace-wide deletion.
	check('a live directory reads as readable', await isReadableDir(dir))
	check('a vanished directory does not', !(await isReadableDir(join(dir, 'nope'))))
})

// A partial walk must say so: its cut point moves between polls, so diffing it
// would invent deletions of files that are still right there.
await withTempDir(async (dir) => {
	writeFileSync(join(dir, 'one.exe'), 'a')
	writeFileSync(join(dir, 'two.exe'), 'b')
	const capped = await scan(dir, { maxFiles: 1 })
	check('flags a walk that hit maxFiles', capped.truncated === true && capped.size === 1)
	check('does not flag a walk that fits', (await scan(dir, { maxFiles: 8 })).truncated === false)
})

console.log('messages')

const gone = [{ path: 'D:\\project\\src\\build.exe', size: 20_480, mtimeMs: Date.now() }]
const flat = buildAlert({
	vanished: gone,
	roots: ['D:\\project'],
	counter: { before: 21, after: 21, profile: 'File_Monitoring' },
})
check('names the vanished file', flat.includes('build.exe'))
check('says the cause was not measured', flat.includes('未测量'))
check('still warns about malicious code', flat.includes('恶意代码'))
check('does not blame Kaspersky outright', !flat.includes('卡巴斯基删除了'))

const risen = buildAlert({
	vanished: gone,
	roots: ['D:\\project'],
	counter: { before: 21, after: 22, profile: 'File_Monitoring' },
})
check('reports a counter rise as a detection', risen.includes('+1'))
check('says the rise is machine-wide, not proof about these files', risen.includes('全机器'))
check('still warns about malicious code when the counter rose', risen.includes('恶意代码'))

// A detection the workspace never saw: the counter rose, no file vanished.
// This is the common timing — the file is eaten inside one poll window.
const unseen = buildAlert({
	vanished: [],
	roots: ['D:\\project'],
	counter: { before: 21, after: 22, profile: 'File_Monitoring' },
})
check('reports a rise with nothing vanished instead of staying silent', unseen.includes('没有捕捉到工作区文件消失'))
check('still warns about malicious code with nothing vanished', unseen.includes('恶意代码'))

const unreadable = buildAlert({ vanished: gone, counter: { before: 21, after: null, profile: 'File_Monitoring', problem: 'Access denied' } })
check('a failed counter read is reported as a failed read', unreadable.includes('读取失败') && unreadable.includes('Access denied'))
check('a failed counter read never claims the counter did not move', !unreadable.includes('未变化'))

const reset = buildAlert({ vanished: gone, counter: { before: 21, after: 3, profile: 'File_Monitoring' } })
check('a counter that went down is not called unchanged', reset.includes('下降') && !reset.includes('未变化'))

const first = buildAlert({ vanished: gone, counter: { before: null, after: 22, profile: 'File_Monitoring' } })
check('a first read without a baseline admits it cannot tell', first.includes('没有更早的基线'))

const section = buildPromptSection({ pollMs: 15_000, profile: 'File_Monitoring', paths: ['D:\\project'] })
check('the prompt section is non-empty text', typeof section === 'string' && section.length > 40)
check('the prompt section tells the agent the counter is machine-wide', section.includes('全机器'))

console.log('plugin wiring')

/** A stand-in Cordis context whose agent enforces the real inbox rules. */
function harness(dir, config) {
	const messages = []
	const malformed = []
	// The real inbox rejects a splice that leaves two pending messages sharing
	// an id, so the stand-in does too: it never drains, which is the worst case.
	const pending = new Set()
	const agent = {
		id: 'test-agent',
		session: { header: { cwd: dir } },
		followup: (message) => {
			if (typeof message?.id !== 'string' || message.id.length === 0) malformed.push('missing id')
			else if (pending.has(message.id)) malformed.push(`duplicate id ${message.id}`)
			else pending.add(message.id)
			if (message?.role !== 'user') malformed.push('role is not user')
			if (message?.content?.[0]?.type !== 'text') malformed.push('content is not a text block')
			if (message?.source?.plugin !== 'dsh-kaspersky') malformed.push('wrong source')
			messages.push({ id: message.id, at: Date.now(), text: message.content[0].text, source: message.source })
		},
	}
	const warnings = []
	const sections = []
	const ctx = {
		logger: { info: () => {}, warn: (message) => warnings.push(message) },
		systemPrompt: { section: (entry) => sections.push(entry) },
		agents: { list: () => [agent], roots: () => [agent] },
		effect: (body) => body(),
	}
	// A nonexistent scanner keeps every poll fast and deterministic: the counter
	// read fails at once instead of spawning avp.com.
	const dispose = apply(ctx, { avp: join(dir, 'no-such-avp.com'), paths: [dir], ...config })
	return { messages, malformed, warnings, sections, dispose }
}

await withTempDir(async (dir) => {
	const h = harness(dir, { pollMs: 1000, timeoutMs: 5000, minAlertIntervalMs: 1000 })
	check('registers exactly one prompt section', h.sections.length === 1)
	check('the section carries a finite order', Number.isFinite(h.sections[0]?.order))
	check('the section is named dsh-kaspersky:guard', h.sections[0]?.name === 'dsh-kaspersky:guard')

	// Two full write → delete cycles, so the second alert lands while the first
	// message is still queued — exactly what a fixed message id would break.
	// Each file lives longer than one poll, or the ledger would never see it.
	for (const name of ['artifact.exe', 'artifact2.exe']) {
		writeFileSync(join(dir, name), 'freshly built')
		await sleep(1500) // the ledger has to remember it before it is deleted
		rmSync(join(dir, name)) // what Kaspersky does to it
	}
	await waitFor(() => h.messages.length >= 2, 25_000)

	const alerts = h.messages
	check('pushes a followup into the agent', alerts.length > 0)
	check('delivers an alert for each deleted artifact', alerts.length === 2, `got ${alerts.length}`)
	check('the alerts carry distinct message ids', new Set(alerts.map((m) => m.id)).size === alerts.length)
	check('the followup is a well-formed user message', h.malformed.length === 0, h.malformed.join('; '))
	check('the followup carries the plugin as its source', alerts[0]?.source?.plugin === 'dsh-kaspersky')
	check('the alert names the deleted artifact', alerts[0]?.text.includes('artifact.exe'))
	check('the alert does not claim Kaspersky deleted it', !alerts[0]?.text.includes('卡巴斯基删除了'))
	check('no poll or dispatch error was logged', h.warnings.length === 0, h.warnings.join('; '))

	// The workspace itself going away must not read as "everything was deleted".
	writeFileSync(join(dir, 'artifact3.exe'), 'freshly built')
	await sleep(1500) // the ledger has to remember it
	const before = h.messages.length
	rmSync(dir, { recursive: true, force: true }) // the whole root, not just the file
	await sleep(2500)
	check('a vanished workspace root raises no alert', h.messages.length === before, `${h.messages.length - before} extra`)

	// A disposed plugin must stop touching the world.
	h.dispose()
	const settled = h.messages.length
	await sleep(1500)
	check('stops polling once disposed', h.messages.length === settled, `${h.messages.length - settled} late`)
})

await withTempDir(async (dir) => {
	// A deletion inside the alert rate limit must be held back, not dropped:
	// the file is already gone, so no later diff can ever find it again.
	const h = harness(dir, { pollMs: 1000, timeoutMs: 5000, minAlertIntervalMs: 4000 })

	writeFileSync(join(dir, 'hold1.exe'), 'first')
	await sleep(1500)
	rmSync(join(dir, 'hold1.exe'))
	await waitFor(() => h.messages.length >= 1, 15_000)
	check('the first deletion alerts immediately', h.messages.length === 1, `got ${h.messages.length}`)

	writeFileSync(join(dir, 'hold2.exe'), 'second')
	await sleep(1500)
	rmSync(join(dir, 'hold2.exe'))
	await sleep(1000)

	// Wait out the rate limit, then give the plugin a fresh reason to report.
	const firstAlert = h.messages[0]
	if (firstAlert) while (Date.now() - firstAlert.at < 4300) await sleep(100)
	writeFileSync(join(dir, 'hold3.exe'), 'third')
	await sleep(1500)
	rmSync(join(dir, 'hold3.exe'))
	await waitFor(() => h.messages.length >= 2, 15_000)

	check('a rate-limited deletion is carried into a later alert',
		h.messages.slice(1).some((m) => m.text.includes('hold2.exe')),
		h.messages.slice(1).map((m) => m.text.slice(0, 60)).join(' | '))
	check('the alerts respect minAlertIntervalMs',
		h.messages.length < 2 || h.messages[1].at - h.messages[0].at >= 4000,
		`gap ${h.messages.length < 2 ? 'n/a' : h.messages[1].at - h.messages[0].at}ms`)
	h.dispose()
})

console.log('live avp.com')

const avp = findAvp('')
if (avp === null) {
	console.log('  skip no avp.com on this machine')
} else {
	const read = await readTotalDetected(avp, 'File_Monitoring', 20_000)
	check(`reads Total detected from ${avp}`, typeof read.total === 'number', read.problem ?? `got ${read.total}`)
	if (typeof read.total === 'number') console.log(`  info Total detected: ${read.total}`)
}

console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed === 0 ? 0 : 1)
