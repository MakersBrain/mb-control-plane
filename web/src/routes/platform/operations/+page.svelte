<script lang="ts">
	import OperatorGuard from '$lib/components/OperatorGuard.svelte';
	import { page } from '$app/state';
	import PlatformNav from '$lib/components/PlatformNav.svelte';
	import StatusBadge from '$lib/components/StatusBadge.svelte';
	import { formatInstant, sentence } from '$lib/format';
	import { request } from '$lib/session.svelte';
	let operations = $state<any[]>([]); let stateFilter = $state(''); let error = $state(''); let loading = $state(true);
	const workshopId = $derived(page.url.searchParams.get('workshop_id') ?? '');
	$effect(() => { stateFilter; void load(); const timer = window.setInterval(() => void load(false), 5000); return () => window.clearInterval(timer); });
	async function load(showError = true) { try { operations = await request<any[]>(`/v1/platform/operations?limit=200${stateFilter ? `&state=${stateFilter}` : ''}${workshopId ? `&workshop_id=${encodeURIComponent(workshopId)}` : ''}`); if (showError) error = ''; } catch (cause) { if (showError) error = cause instanceof Error ? cause.message : String(cause); } finally { loading = false; } }
</script>

<svelte:head><title>Platform operations · MakersBrain</title></svelte:head>
<OperatorGuard>
	<header class="page-header"><div><p class="eyebrow">Platform administration</p><h1>Durable operations</h1><p class="muted">Queue progress, bounded attempts, and safe retry state across workers.</p></div><button class="secondary" onclick={() => load()}>Refresh</button></header>
	<PlatformNav />
	{#if error}<p class="error">{error}</p>{/if}
	<div class="card filters"><label>State<select bind:value={stateFilter}><option value="">All states</option><option value="pending">Pending</option><option value="in_flight">In progress</option><option value="awaiting_reconciliation">Reconciling</option><option value="dead_letter">Needs attention</option><option value="succeeded">Succeeded</option></select></label><span class="muted">Showing the newest {operations.length} operations.</span></div>
	<section class="section card table-wrap">{#if loading}<div class="empty">Loading operations…</div>{:else if operations.length === 0}<div class="empty">No operations in this state.</div>{:else}<table><thead><tr><th>Operation</th><th>Workshop</th><th>State</th><th>Attempts</th><th>Progress</th><th>Started</th></tr></thead><tbody>{#each operations as item (item.id)}<tr><td><a href={`/operations/${item.id}`}><strong>{sentence(item.kind)}</strong></a>{#if item.failure_class}<div class="muted">{sentence(item.failure_class)}</div>{/if}</td><td>{#if item.workshop_id}<a href={`/platform/workshops/${item.workshop_id}`}>{item.workshop_name ?? item.workshop_id}</a>{:else}Platform{/if}</td><td><StatusBadge state={item.state} /></td><td>{item.attempt}/{item.max_attempts}</td><td>{item.progress_percent ?? 0}%{#if item.progress_message}<div class="muted">{item.progress_message}</div>{/if}</td><td>{formatInstant(item.created_at)}</td></tr>{/each}</tbody></table>{/if}</section>
</OperatorGuard>

<style>.filters{display:flex;align-items:end;gap:1rem}.filters label{min-width:14rem}@media(max-width:600px){.filters{display:grid}.filters label{min-width:0}}</style>
