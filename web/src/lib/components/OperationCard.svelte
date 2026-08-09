<script lang="ts">
	import { request } from '$lib/session.svelte';
	import { formatInstant, isPending, sentence } from '$lib/format';
	import type { Operation } from '$lib/types';
	import ProgressBar from './ProgressBar.svelte';
	import StatusBadge from './StatusBadge.svelte';

	let {
		id,
		compact = false,
		onsettled
	}: { id: string; compact?: boolean; onsettled?: () => void } = $props();
	let operation = $state<Operation>();
	let error = $state('');
	let retrying = $state(false);
	let settledNotified = false;

	$effect(() => {
		id;
		settledNotified = false;
		void load();
		const timer = window.setInterval(() => {
			if (isPending(operation?.state)) void load(false);
		}, 3000);
		return () => window.clearInterval(timer);
	});

	async function load(showError = true) {
		try {
			operation = await request<Operation>(`/v1/operations/${id}`);
			if (!isPending(operation.state) && !settledNotified) {
				settledNotified = true;
				onsettled?.();
			}
			if (showError) error = '';
		} catch (cause) {
			if (showError) error = cause instanceof Error ? cause.message : String(cause);
		}
	}

	async function retry() {
		retrying = true;
		error = '';
		try {
			await request(`/v1/operations/${id}/retry`, { method: 'POST' });
			settledNotified = false;
			await load();
		} catch (cause) {
			error = cause instanceof Error ? cause.message : String(cause);
		} finally {
			retrying = false;
		}
	}
</script>

<article class:compact class="card operation-card">
	{#if error}<p class="error">{error}</p>{/if}
	{#if operation}
		<div class="row">
			<div>
				<strong>{sentence(operation.kind)}</strong>
				{#if !compact}<div class="muted">Started {formatInstant(operation.created_at)} · attempt {operation.attempt} of {operation.max_attempts}</div>{/if}
			</div>
			<StatusBadge state={operation.state} />
		</div>
		{#if isPending(operation.state)}
			<ProgressBar value={operation.progress_percent ?? 0} />
			<p class="muted operation-message">{operation.progress_message ?? sentence(operation.progress_phase ?? 'Waiting for a worker')} · {operation.progress_percent ?? 0}%</p>
		{:else if operation.state === 'dead_letter'}
			<div class="row operation-failure">
				<p><strong>Safe failure:</strong> {sentence(operation.failure_class ?? 'operation failed')}</p>
				<button class="secondary" disabled={retrying} onclick={retry}>{retrying ? 'Retrying…' : 'Retry safely'}</button>
			</div>
		{:else if !compact}
			<p class="muted">Finished {formatInstant(operation.finished_at)}</p>
		{/if}
	{:else if !error}
		<p class="muted">Loading operation…</p>
	{/if}
</article>
