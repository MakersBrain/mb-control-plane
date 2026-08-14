<script lang="ts">
	import OperatorGuard from '$lib/components/OperatorGuard.svelte';
	import PlatformNav from '$lib/components/PlatformNav.svelte';
	import StatusBadge from '$lib/components/StatusBadge.svelte';
	import { formatInstant, sentence } from '$lib/format';
	import { request } from '$lib/session.svelte';
	import type { PlatformOverviewResponse } from '$lib/generated/control-api';
	let overview = $state<PlatformOverviewResponse>();
	let error = $state('');
	let loading = $state(true);
	$effect(() => { void load(); const timer = window.setInterval(() => void load(false), 10000); return () => window.clearInterval(timer); });
	async function load(showError = true) { try { overview = await request<PlatformOverviewResponse>('/v1/platform/overview'); if (showError) error = ''; } catch (cause) { if (showError) error = cause instanceof Error ? cause.message : String(cause); } finally { loading = false; } }
</script>

<svelte:head><title>Platform overview · MakersBrain</title></svelte:head>
<OperatorGuard>
	<header class="page-header"><div><p class="eyebrow">Platform administration</p><h1>Service overview</h1><p class="muted">Fleet state, durable work, and safe failure classes across every workshop.</p></div><button class="secondary" onclick={() => load()}>Refresh</button></header>
	<PlatformNav />
	{#if error}<p class="error" role="alert">{error}</p>{/if}
	{#if loading}<div class="card empty">Loading platform state…</div>{:else if overview}
		<section class="metric-grid" aria-label="Platform summary">
			<a class="card metric" href="/platform/workshops"><span class="metric-label">Workshops</span><strong>{overview.workshops.total}</strong><span class="muted">{overview.workshops.healthy} healthy · {overview.workshops.attention} lifecycle alerts</span></a>
			<div class="card metric"><span class="metric-label">Accounts</span><strong>{overview.users.total}</strong><span class="muted">{overview.users.disabled} disabled</span></div>
			<a class="card metric" href="/platform/operations"><span class="metric-label">Queued work</span><strong>{overview.operations.queued}</strong><span class="muted">{overview.operations.running} running · {overview.operations.failed} failed</span></a>
			<div class="card metric"><span class="metric-label">Degraded services</span><strong class:bad-number={overview.degraded_services > 0}>{overview.degraded_services}</strong><span class="muted">Odoo and Paperless instances</span></div>
		</section>
		<section class="section"><div class="section-header"><div><h2>Needs attention</h2><p class="muted">Failed, running, and reconciling operations; secrets and provider payloads are excluded.</p></div><a href="/platform/operations">All operations →</a></div>
			<div class="card table-wrap">{#if overview.attention.length === 0}<div class="empty">No operations need attention.</div>{:else}<table><thead><tr><th>Operation</th><th>Workshop</th><th>State</th><th>Started</th></tr></thead><tbody>{#each overview.attention as item (item.id)}<tr><td><a href={`/operations/${item.id}`}><strong>{sentence(item.kind)}</strong></a>{#if item.failure_class}<div class="muted">{sentence(item.failure_class)}</div>{/if}</td><td>{item.workshop_name ?? 'Platform'}</td><td><StatusBadge state={item.state} /></td><td>{formatInstant(item.created_at)}</td></tr>{/each}</tbody></table>{/if}</div>
		</section>
	{/if}
</OperatorGuard>

<style>
	.metric-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:1rem}.metric{display:grid;gap:.25rem;text-decoration:none}.metric strong{font-family:'Newsreader',Georgia,serif;font-size:2.25rem}.metric-label{font-size:.76rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}.bad-number{color:var(--danger)}@media(max-width:900px){.metric-grid{grid-template-columns:repeat(2,1fr)}}@media(max-width:520px){.metric-grid{grid-template-columns:1fr}}
</style>
