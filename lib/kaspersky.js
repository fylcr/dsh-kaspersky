/**
 * Talking to Kaspersky through `avp.com`.
 *
 * Measured on Kaspersky 21.26 (KAVKISKTS, zh-CN home product) on Windows:
 *
 * - `avp.com STATISTICS <profile>` needs **no login** and prints a block that
 *   contains a `Total detected:` counter. That counter is the only login-free
 *   "something was just detected" signal the product exposes.
 * - `avp.com REPORT <profile> /RA:<file>` carries the threat *names*, but it is
 *   login-gated: without `/login=` and `/password=` it prints
 *   `Parameters /login=<login> /password=<password> are required for this action.`
 *   and writes no file. So names are opt-in configuration, never a guess.
 *
 * avp.com prints English regardless of the system locale, so the parsing below
 * keys on ASCII and survives a non-UTF-8 console codepage.
 *
 * @module dsh-kaspersky/kaspersky
 */

import { execFile } from 'node:child_process'
import { existsSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

/** Vendor directories that hold a versioned `Kaspersky <version>` install. */
const VENDOR_DIRS = [
	'C:\\Program Files (x86)\\Kaspersky Lab',
	'C:\\Program Files\\Kaspersky Lab',
]

/**
 * Locate `avp.com`.
 *
 * An explicit command is returned untouched — it may be a bare name resolved
 * through `PATH`, which `existsSync` cannot check. Otherwise the known vendor
 * directories are scanned for an `avp.com` inside a versioned `Kaspersky`
 * folder, so a product upgrade does not break the plugin the way a hard-coded
 * version number would.
 *
 * @param explicit - configured command, if any.
 * @returns the command to run, or null when nothing was found.
 */
export function findAvp(explicit) {
	if (explicit) return explicit
	for (const root of VENDOR_DIRS) {
		let entries
		try {
			entries = readdirSync(root, { withFileTypes: true })
		} catch {
			continue
		}
		for (const entry of entries) {
			if (!entry.isDirectory() || !/^kaspersky/i.test(entry.name)) continue
			const candidate = join(root, entry.name, 'avp.com')
			if (existsSync(candidate)) return candidate
		}
	}
	return null
}

/**
 * Run one avp.com command and settle with its output instead of rejecting.
 *
 * avp.com exits non-zero for several ordinary outcomes (an unknown profile
 * name, a scan that detected something), so the caller decides what the exit
 * code means by reading the output.
 */
export function runAvp(avp, args, timeoutMs) {
	return new Promise((resolve) => {
		execFile(
			avp,
			args,
			{ timeout: timeoutMs, windowsHide: true, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 },
			(error, stdout, stderr) => resolve({ error, stdout: stdout ?? '', stderr: stderr ?? '' }),
		)
	})
}

/** Matches the counter line in a STATISTICS block, with or without `; ` prefixes. */
const TOTAL_DETECTED = /^[;\s]*Total detected:\s*(\d+)\s*$/im

/**
 * Read the `Total detected:` counter out of a STATISTICS block.
 *
 * @returns the counter, or null when the block does not carry one.
 */
export function parseTotalDetected(text) {
	const match = TOTAL_DETECTED.exec(text ?? '')
	return match ? Number(match[1]) : null
}

/**
 * Read the real-time protection counter.
 *
 * @returns `{ total }` on success, `{ problem }` on a readable failure. A
 *   failure is never reported as a detection.
 */
export async function readTotalDetected(avp, profile, timeoutMs) {
	if (!avp) return { problem: 'avp.com not found' }
	const { error, stdout, stderr } = await runAvp(avp, ['STATISTICS', profile], timeoutMs)
	const total = parseTotalDetected(stdout)
	if (total !== null) return { total }
	const detail = (stderr || stdout || String(error?.message ?? '')).trim().split('\n')[0]
	return { problem: detail || 'no counter in avp.com STATISTICS output' }
}

/**
 * Ask avp.com for the full event report, which is the only place threat names
 * appear. Requires configured credentials; the returned path is the report
 * file the agent can read itself.
 *
 * @returns `{ path }` when a report was written, `{ problem }` otherwise.
 */
export async function writeThreatReport(avp, options) {
	const { profile, login, password, outFile, timeoutMs, all = false } = options
	if (!avp) return { problem: 'avp.com not found' }
	if (!login || !password) return { problem: 'no avp.com credentials configured' }
	const { error, stdout, stderr } = await runAvp(
		avp,
		[
			'REPORT',
			profile,
			`${all ? '/RA' : '/R'}:${outFile}`,
			`/login=${login}`,
			`/password=${password}`,
		],
		timeoutMs,
	)
	// The report is written by another process, so it can appear, disappear or
	// be locked between these two calls (Kaspersky's self-defence does exactly
	// that). A failed check must degrade to "no report", never crash the poll.
	let written = false
	try {
		written = statSync(outFile).size > 0
	} catch {
		written = false
	}
	if (written) return { path: outFile }
	const detail = (stderr || stdout || String(error?.message ?? '')).trim().split('\n')[0]
	return { problem: detail || 'avp.com REPORT wrote no file' }
}
