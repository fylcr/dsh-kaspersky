/**
 * The workspace ledger: which files existed, and which of them disappeared.
 *
 * The plugin's job is to notice a *deletion* that Kaspersky performed, so it
 * needs a memory of what used to be there. The ledger is that memory: a plain
 * map from absolute path to `{ size, mtimeMs }`, produced by a bounded walk.
 *
 * One full walk per poll, rather than `fs.watch`: a watcher is cheaper but
 * reports per-event and drops events under load, and a missed event is
 * precisely the failure this plugin exists to catch. A walk is deterministic —
 * whatever the filesystem says at poll time is the truth the diff is computed
 * against.
 *
 * @module dsh-kaspersky/ledger
 */

import { readdir, stat } from 'node:fs/promises'
import { join } from 'node:path'

/** Directory names never descended into; they are large and never artifacts. */
export const DEFAULT_IGNORE = ['node_modules', '.git']

/** Concurrent `stat` calls. Enough to hide latency without swamping a spindle. */
const STAT_BATCH = 64

/**
 * Walk one root and record every regular file under it.
 *
 * Symlinks are skipped: `dirent.isFile()`/`isDirectory()` are false for them,
 * which also makes a symlink cycle impossible.
 *
 * @param root - absolute directory to walk; a missing root yields an empty map.
 * @param options - `ignore` directory names, and the `maxFiles` bound that
 *   keeps a runaway workspace from turning a poll into a minutes-long walk.
 * @returns a fresh Map from absolute path to `{ size, mtimeMs }`.
 */
export async function scan(root, options = {}) {
	const { ignore = DEFAULT_IGNORE, maxFiles = 50_000 } = options
	const skip = new Set(ignore)
	const files = new Map()
	const queue = [root]

	while (queue.length > 0) {
		const dir = queue.pop()
		let entries
		try {
			entries = await readdir(dir, { withFileTypes: true })
		} catch {
			continue // vanished or unreadable between polls: not this poll's problem
		}
		const here = []
		for (const entry of entries) {
			if (entry.isDirectory()) {
				if (!skip.has(entry.name)) queue.push(join(dir, entry.name))
			} else if (entry.isFile()) {
				here.push(join(dir, entry.name))
			}
		}
		for (let at = 0; at < here.length; at += STAT_BATCH) {
			if (files.size >= maxFiles) return files
			const batch = here.slice(at, at + STAT_BATCH)
			const stats = await Promise.all(batch.map((path) => stat(path).catch(() => undefined)))
			for (let i = 0; i < batch.length; i += 1) {
				const info = stats[i]
				if (info === undefined) continue // deleted mid-walk; the next diff reports it
				files.set(batch[i], { size: info.size, mtimeMs: info.mtimeMs })
			}
		}
	}
	return files
}

/**
 * Whether a root can be listed right now.
 *
 * `scan` cannot tell "this directory is empty" from "this directory could not
 * be opened", and the difference decides whether a whole workspace is reported
 * as deleted. Callers ask this before trusting an empty walk.
 *
 * @param root - absolute directory to test.
 * @returns true when the directory lists, false when it is gone or unreadable.
 */
export async function isReadableDir(root) {
	try {
		await readdir(root)
		return true
	} catch {
		return false
	}
}

/**
 * Files that were in `previous`, are gone from `next`, and were touched
 * recently enough to be something the agent just produced.
 *
 * The age filter is what separates "the workspace changed" from "an artifact
 * was removed": a file nobody has written since this morning is not evidence
 * about the code that was just written.
 *
 * @param previous - ledger from the earlier scan.
 * @param next - ledger from the current scan.
 * @param options - `now` (ms) and the `maxAgeMs` window.
 * @returns vanished entries, newest first, as `{ path, size, mtimeMs }`.
 */
export function diff(previous, next, options = {}) {
	const { now = Date.now(), maxAgeMs } = options
	const cutoff = maxAgeMs === undefined ? -Infinity : now - maxAgeMs
	const vanished = []
	for (const [path, before] of previous) {
		if (next.has(path)) continue
		if (before.mtimeMs < cutoff) continue
		vanished.push({ path, size: before.size, mtimeMs: before.mtimeMs })
	}
	vanished.sort((a, b) => b.mtimeMs - a.mtimeMs)
	return vanished
}
