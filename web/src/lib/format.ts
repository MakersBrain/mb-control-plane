const ROLE_LABELS: Record<string, string> = {
	viewer: 'Viewer',
	artisan: 'Artisan',
	accountant: 'Accountant',
	studio_manager: 'Studio manager',
	owner: 'Owner'
};

const STATE_LABELS: Record<string, string> = {
	awaiting_reconciliation: 'Reconciling',
	dead_letter: 'Needs attention',
	in_flight: 'In progress',
	past_due: 'Past due'
};

export function roleLabel(value: string): string {
	return ROLE_LABELS[value] ?? sentence(value);
}

export function stateLabel(value: string): string {
	return STATE_LABELS[value] ?? sentence(value);
}

export function sentence(value: string): string {
	const text = value.replaceAll(/[._-]+/g, ' ');
	return text ? text[0].toUpperCase() + text.slice(1) : 'Unknown';
}

export function formatInstant(value?: string | null): string {
	if (!value) return '—';
	const parsed = new Date(value);
	if (Number.isNaN(parsed.getTime())) return '—';
	return new Intl.DateTimeFormat(undefined, {
		dateStyle: 'medium',
		timeStyle: 'short'
	}).format(parsed);
}

export function formatBytes(value?: number): string {
	if (value == null || !Number.isFinite(value)) return '—';
	const units = ['B', 'kB', 'MB', 'GB', 'TB'];
	let size = value;
	let unit = 0;
	while (size >= 1024 && unit < units.length - 1) {
		size /= 1024;
		unit += 1;
	}
	return `${size < 10 && unit > 0 ? size.toFixed(1) : Math.round(size)} ${units[unit]}`;
}

export function isPending(state?: string | null): boolean {
	return !!state && ['pending', 'in_flight', 'awaiting_reconciliation', 'requested', 'installing', 'restricting', 'provisioning'].includes(state);
}

export function tone(state?: string): 'good' | 'warn' | 'bad' | 'neutral' {
	if (!state) return 'neutral';
	if (['active', 'ready', 'enabled', 'succeeded', 'sent', 'accepted', 'trial', 'verified'].includes(state)) return 'good';
	if (['failed', 'degraded', 'dead_letter', 'disabled', 'restricted', 'past_due', 'suspended'].includes(state)) return 'bad';
	if (['deferred', 'sending'].includes(state)) return 'warn';
	if (isPending(state)) return 'warn';
	return 'neutral';
}
