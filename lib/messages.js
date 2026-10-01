/**
 * The two pieces of text this plugin produces.
 *
 * Both are Chinese on purpose: the machine this was built for runs a zh-CN
 * Kaspersky on a zh-CN Windows with a Chinese-speaking user, and these strings
 * are read by that user. Translating them is a copy change in this one file.
 *
 * @module dsh-kaspersky/messages
 */

/** Human-readable size, rounded to something a person can compare at a glance. */
export function formatSize(bytes) {
	if (!Number.isFinite(bytes)) return '未知大小'
	if (bytes < 1024) return `${bytes} B`
	if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
	return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

/** Local wall-clock time of a `mtimeMs` stamp. */
export function formatTime(mtimeMs) {
	if (!Number.isFinite(mtimeMs)) return '未知时间'
	const d = new Date(mtimeMs)
	const pad = (n) => String(n).padStart(2, '0')
	return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

/**
 * One sentence describing what the antivirus counter did, kept truthful about
 * what was and was not measured.
 *
 * A rise attributes the deletion; no rise means the cause was not measured and
 * the text says so instead of blaming Kaspersky.
 */
function describeCounter(counter) {
	if (counter === null || counter === undefined) {
		return '卡巴斯基查杀计数：读取失败（avp.com 不可用或未返回计数）——删除原因未测量。'
	}
	const { before, after, profile } = counter
	if (before === null) {
		return `卡巴斯基查杀计数（${profile}）：基线 ${after}（本次是插件的第一次读取，无法判断是否刚刚上升）。`
	}
	if (after > before) {
		return `卡巴斯基查杀计数（${profile} "Total detected"）：${before} → ${after}（+${after - before}）。`
	}
	return `卡巴斯基查杀计数（${profile} "Total detected"）：${before} → ${after}（未变化）——删除原因未测量，不能断定是卡巴斯基所为。`
}

/** One line about the threat names, which live behind a login-gated report. */
function describeThreat(threat) {
	if (threat && threat.path) return `威胁名称：见卡巴斯基报告 ${threat.path}`
	const problem = threat && threat.problem ? threat.problem : '未配置 avp.com 登录名/密码'
	return `威胁名称：未获取（${problem}）`
}

/**
 * The message pushed into the agent when artifacts disappear.
 *
 * @param input - `vanished` (from `ledger.diff`), `roots` watched, `counter`,
 *   `threat`, and `now`.
 * @returns the message text.
 */
export function buildAlert({ vanished, roots = [], counter = null, threat = null, now = Date.now() }) {
	// Only name the antivirus as the deleter once its own counter confirms it.
	const detected = counter !== null && counter.before !== null && counter.after > counter.before
	const title = detected
		? '🛡️ **dsh-kaspersky：卡巴斯基删除了刚生成的产物**'
		: '🛡️ **dsh-kaspersky：工作区里有刚生成的产物消失了**'
	const lines = [title, '']
	lines.push('本次轮询前存在、现在已消失的文件：')
	for (const file of vanished) {
		lines.push(`- \`${file.path}\`（${formatSize(file.size)}，最后修改 ${formatTime(file.mtimeMs)}）`)
	}
	lines.push('')
	if (roots.length > 0) lines.push(`监视目录：${roots.map((r) => `\`${r}\``).join('、')}`)
	lines.push(describeCounter(counter))
	lines.push(describeThreat(threat))
	lines.push('')
	lines.push('⚠️ **你刚才生成的代码或产物可能包含恶意代码，请先确认再继续。**')
	lines.push('不要直接重新构建或重新生成：先查看被删产物对应的源码与生成它的逻辑，')
	lines.push('判断这是误报还是真实风险，把结论告诉用户之后再继续。')
	lines.push('')
	lines.push(`（dsh-kaspersky 于 ${formatTime(now)} 报告）`)
	return lines.join('\n')
}

/**
 * The standing system-prompt section, so the agent knows the guard exists
 * before it ever trips.
 */
export function buildPromptSection({ pollMs, profile, paths = [] }) {
	const seconds = Math.round(pollMs / 1000)
	const extra = paths.length > 0 ? `除每个会话的工作目录外，还监视：${paths.map((p) => `\`${p}\``).join('、')}。` : ''
	return [
		'## 卡巴斯基产物守卫（dsh-kaspersky）',
		'本机装有卡巴斯基，它会实时删除被判定为恶意的文件——包括你刚刚生成的构建产物、测试样本和可执行文件。',
		`插件每 ${seconds} 秒扫描一次工作区：`
			+ `若产物消失且卡巴斯基的查杀计数（\`avp.com STATISTICS ${profile}\`）上升，`
			+ '就会立刻把被删文件、计数变化和风险提醒推给你。',
		extra,
		'收到这类提醒时：不要直接重建产物；先检查被删产物对应的源码和生成逻辑，',
		'判断是误报还是真实风险，再向用户说明结论。若只是文件消失而计数未上升，说明原因未测量，不要断言是卡巴斯基所为。',
	]
		.filter(Boolean)
		.join('\n')
}
