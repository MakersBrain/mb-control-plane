<script lang="ts">
	import { page } from '$app/state';
	import WorkshopNav from '$lib/components/WorkshopNav.svelte';
	import StatusBadge from '$lib/components/StatusBadge.svelte';
	import OperationCard from '$lib/components/OperationCard.svelte';
	import { request } from '$lib/session.svelte';
	import type { WorkshopSummary } from '$lib/types';

	type Check = { key:string; label:string; ready:boolean; count?:number; next_action:string; href?:string };
	type Issue = { key:string; category:string; state:string; count:number; safe_error_class?:string; next_action:string; href?:string; operation_id?:string; can_retry:boolean };
	type Dashboard = { state:string; version:number; etag:string; operation_id?:string; operation_state?:string; last_checked_at?:string; completed_at?:string; checks:Check[]; issues:Issue[]; can_manage:boolean; odoo_url?:string };

	const id = $derived(page.params.id ?? '');
	let workshop = $state<WorkshopSummary>();
	let dashboard = $state<Dashboard>();
	let error = $state(''); let notice = $state(''); let busy = $state('');
	const ready = $derived(Boolean(dashboard && dashboard.checks.every((check) => check.ready) && dashboard.issues.length === 0));

	$effect(() => { id; void load(); });
	async function load() {
		try {
			[workshop, dashboard] = await Promise.all([
				request<WorkshopSummary>(`/v1/workshops/${id}`),
				request<Dashboard>(`/v1/workshops/${id}/webshop`)
			]);
			error = '';
		} catch (cause) { error = cause instanceof Error ? cause.message : String(cause); }
	}
	async function refresh() {
		if (!dashboard) return; busy = 'refresh'; error = ''; notice = '';
		try {
			const result = await request<{operation_id?:string}>(`/v1/workshops/${id}/webshop/onboarding/refresh`, { method:'POST', headers:{'idempotency-key':crypto.randomUUID(),'if-match':dashboard.etag} });
			notice = 'The readiness observation is running. You can leave this page and resume later.';
			await load();
			if (result.operation_id && dashboard) dashboard.operation_id = result.operation_id;
		} catch (cause) { error = cause instanceof Error ? cause.message : String(cause); }
		finally { busy = ''; }
	}
	async function complete() {
		if (!dashboard) return; busy = 'complete'; error = ''; notice = '';
		try {
			await request(`/v1/workshops/${id}/webshop/onboarding/complete`, { method:'POST', headers:{'idempotency-key':crypto.randomUUID(),'if-match':dashboard.etag} });
			notice = 'Webshop setup is complete. The same page remains your operational recovery dashboard.';
			await load();
		} catch (cause) { error = cause instanceof Error ? cause.message : String(cause); }
		finally { busy = ''; }
	}
</script>

<svelte:head><title>Webshop · {workshop?.display_name || 'MakersBrain'}</title></svelte:head>
<p><a href="/">← Workshops</a></p>
<header class="page-header"><div><p class="eyebrow">{workshop?.display_name ?? 'Workshop'}</p><h1>Webshop setup & recovery</h1><p class="muted">A saved launch checklist and one place to resolve payments, fulfilment, returns, domains and transactional mail.</p></div>{#if dashboard}<StatusBadge state={dashboard.state} />{/if}</header>
<WorkshopNav {id} />
{#if error}<p class="error" role="alert">{error}</p>{/if}
{#if notice}<p class="notice" role="status">{notice}</p>{/if}

{#if dashboard}
	<section class="section">
		<div class="section-header"><div><h2>Launch checklist</h2><p class="muted">Observed configuration is saved after each check. Closing the browser does not lose progress.{#if dashboard.last_checked_at} Last checked {new Date(dashboard.last_checked_at).toLocaleString()}.{/if}</p></div><button disabled={!dashboard.can_manage || busy !== ''} onclick={refresh}>{busy === 'refresh' ? 'Checking…' : 'Refresh checks'}</button></div>
		<div class="checklist">
			{#each dashboard.checks as check (check.key)}
				<article class="card check" class:ready={check.ready}><div class="check-mark" aria-hidden="true">{check.ready ? '✓' : '!'}</div><div><div class="row"><strong>{check.label}</strong><StatusBadge state={check.ready ? 'ready' : 'action_required'} /></div>{#if check.count !== undefined}<p class="muted">Observed count: {check.count}</p>{/if}{#if !check.ready}<p>{check.next_action}</p>{#if check.href}<a href={check.href}>Open configuration →</a>{/if}{/if}</div></article>
			{/each}
		</div>
		{#if dashboard.operation_id && ['pending','in_flight','awaiting_reconciliation'].includes(dashboard.operation_state ?? '')}<OperationCard id={dashboard.operation_id} onsettled={load} />{/if}
		<div class="form-actions"><button disabled={!dashboard.can_manage || !ready || dashboard.state === 'completed' || busy !== ''} onclick={complete}>{dashboard.state === 'completed' ? 'Setup completed' : busy === 'complete' ? 'Completing…' : 'Complete setup'}</button></div>
	</section>

	<section class="section"><div class="section-header"><div><h2>Operational attention</h2><p class="muted">Only safe error classes and direct recovery actions are shown; credentials and provider payloads remain hidden.</p></div><span class="badge">{dashboard.issues.length}</span></div>
		{#if dashboard.issues.length === 0}<div class="card empty">No payment, shipment, return, domain or delivery issue needs attention.</div>{/if}
		<div class="issues">{#each dashboard.issues as issue (issue.key)}<article class="card stack"><div class="row"><div><strong>{issue.category.replaceAll('_',' ')}</strong><div class="muted">{issue.count} item{issue.count === 1 ? '' : 's'}</div></div><StatusBadge state={issue.state} /></div>{#if issue.safe_error_class}<p class="error">{issue.safe_error_class.replaceAll('_',' ')}</p>{/if}<p>{issue.next_action}</p>{#if issue.href}<a href={issue.href} target={issue.href.startsWith('http') ? '_blank' : undefined} rel={issue.href.startsWith('http') ? 'noreferrer' : undefined}>Open recovery action →</a>{/if}{#if issue.operation_id}<OperationCard id={issue.operation_id} compact onsettled={load} />{/if}</article>{/each}</div>
	</section>
{/if}

<style>
	.checklist,.issues{display:grid;gap:1rem}.check{display:grid;grid-template-columns:2rem 1fr;gap:1rem}.check-mark{width:2rem;height:2rem;border-radius:50%;display:grid;place-items:center;background:var(--surface-muted);font-weight:700}.check.ready .check-mark{background:var(--success-soft);color:var(--success)}.check .row{align-items:center}.issues{grid-template-columns:repeat(auto-fit,minmax(280px,1fr))}.form-actions{margin-top:1rem;display:flex;justify-content:flex-end}
</style>
