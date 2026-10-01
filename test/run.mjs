/**
 * `npm test` — one runnable check for every claim the README makes.
 *
 * The first four groups are pure and always run. The last group is a live
 * probe: it runs only if avp.com is actually installed, so the suite stays
 * green on a machine without Kaspersky.
 */

import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { apply } from '../index.js'
import { findAvp, parseTotalDetected, readTotalDetected } from '../lib/kaspersky.js'
import { diff, scan } from '../lib/ledger.js'
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

		rmSync(join(dir, 'src', 'build.exe'))
		const after = await scan(dir)
		const vanished = diff(before, after, { maxAgeMs: 60_000 })
		check('reports the deleted file', vanished.length === 1 && vanished[0].path.endsWith('build.exe'))

		const aged = diff(before, after, { now: Date.now() + 3_600_000, maxAgeMs: 60_000 })
		check('ignores deletions older than artifactMaxAgeMs', aged.length === 0)

		check('never reports new files as vanished', diff(after, await scan(dir), { maxAgeMs: 60_000 }).length === 0)
		check('a missing root scans as empty rather than throwing', (await scan(join(dir, 'nope'))).size === 0)
})

console.log('messages')

const vanished = [{ path: 'D:\\project\\src\\build.exe', size: 20_480, mtimeMs: Date.now() }]
const flat = buildAlert({
	vanished,
	roots: ['D:\\project'],
	counter: { before: 21, after: 21, profile: 'File_Monitoring' },
})
check('names the vanished file', flat.includes('build.exe'))
check('says the cause was not measured', flat.includes('未测量'))
check('still warns about malicious code', flat.includes('恶意代码'))
check('does not blame Kaspersky outright', !flat.includes('卡巴斯基删除了'))

const risen = buildAlert({
	vanished,
	roots: ['D:\\project'],
	counter: { before: 21, after: 22, profile: 'File_Monitoring' },
})
check('reports a counter rise as a detection', risen.includes('+1'))
check('blames Kaspersky only once its counter rose', risen.includes('卡巴斯基删除了'))

const section = buildPromptSection({ pollMs: 15_000, profile: 'File_Monitoring', paths: ['D:\\project'] })
check('the prompt section is non-empty text', typeof section === 'string' && section.length > 40)

console.log('plugin wiring')

// `apply` is driven against a stand-in Cordis context, because that is the
// seam that actually breaks: a wrong service name or a wrong message shape
// only shows up here, not in the pure helpers.
await withTempDir(async (dir) => {
	const delivered = []
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
			delivered.push(message)
		},
	}
	const sections = []
	const ctx = {
		logger: { info: () => {}, warn: (message) => delivered.push({ warning: message }) },
		systemPrompt: { section: (entry) => sections.push(entry) },
		agents: { list: () => [agent], roots: () => [agent] },
		effect: (body) => body(),
	}

	const dispose = apply(ctx, { paths: [dir], pollMs: 100, timeoutMs: 15_000, minAlertIntervalMs: 1000 })
	check('registers exactly one prompt section', sections.length === 1)
	check('the section carries a finite order', Number.isFinite(sections[0]?.order))
	check('the section is named dsh-kaspersky:guard', sections[0]?.name === 'dsh-kaspersky:guard')

	// Two full write → delete cycles, so the second alert lands while the first
	// message is still queued — exactly what a fixed message id would break.
	for (const name of ['artifact.exe', 'artifact2.exe']) {
		writeFileSync(join(dir, name), 'freshly built')
		await new Promise((resolve) => setTimeout(resolve, 600)) // ledger remembers it
		rmSync(join(dir, name)) // what Kaspersky does to it
		await new Promise((resolve) => setTimeout(resolve, 1800)) // next poll notices
	}
	dispose()

	const alerts = delivered.filter((message) => message?.content)
	check('pushes a followup into the agent', alerts.length > 0)
	check('delivers an alert for each deleted artifact', alerts.length === 2, `got ${alerts.length}`)
	check('the alerts carry distinct message ids', new Set(alerts.map((m) => m.id)).size === alerts.length)
	check('the followup is a well-formed user message', malformed.length === 0, malformed.join('; '))
	check('the followup carries the plugin as its source', alerts[0]?.source?.plugin === 'dsh-kaspersky')
	check('the alert names the deleted artifact', alerts[0]?.content?.[0]?.text?.includes('artifact.exe'))
	check('no poll or dispatch error was logged', !delivered.some((message) => message.warning))
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
