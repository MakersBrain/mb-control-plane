<script lang="ts">
	import { page } from '$app/state';
	import OperationCard from '$lib/components/OperationCard.svelte';
	import StatusBadge from '$lib/components/StatusBadge.svelte';
	import WorkshopNav from '$lib/components/WorkshopNav.svelte';
	import { isPending, sentence } from '$lib/format';
	import { request } from '$lib/session.svelte';
	import type { Module, WorkshopSummary } from '$lib/types';

	const id = $derived(page.params.id ?? '');
	let workshop = $state<WorkshopSummary>();
	let modules = $state<Module[]>([]);
	let error = $state('');
	let notice = $state('');
	let busy = $state('');
	const hasPending = $derived(modules.some((module) => isPending(module.state)));

	$effect(() => {
		id;
		void load();
		const timer = window.setInterval(() => { if (hasPending) void load(false); }, 4000);
		return () => window.clearInterval(timer);
	});

	async function load(showError = true) {
		try {
			[workshop, modules] = await Promise.all([request<WorkshopSummary>(`/v1/workshops/${id}`), request<Module[]>(`/v1/workshops/${id}/modules`)]);
			if (showError) error = '';
		} catch (cause) { if (showError) error = cause instanceof Error ? cause.message : String(cause); }
	}

	async function enable(module: Module) {
		busy = module.key; error = ''; notice = '';
		try {
			await request(`/v1/workshops/${id}/modules/${module.key}/enable`, { method: 'POST', headers: { 'idempotency-key': crypto.randomUUID(), 'if-match': module.etag } });
			notice = `${moduleName(module.key)} is queued for installation.`;
			await load();
		} catch (cause) { error = cause instanceof Error ? cause.message : String(cause); }
		finally { busy = ''; }
	}

	const missingDependencies = (module: Module) => module.dependencies.filter((key) => !modules.some((candidate) => candidate.key === key && candidate.state === 'enabled'));
	const moduleName = (key: string) => modules.find((module) => module.key === key)?.name || sentence(key);
</script>

<svelte:head><title>Modules · {workshop?.display_name || 'MakersBrain'}</title></svelte:head>
<p><a href="/">← Workshops</a></p>
<header class="page-header"><div><p class="eyebrow">{workshop?.display_name ?? 'Workshop'}</p><h1>Modules</h1><p class="muted">Enable supported services without handling downstream credentials or raw configuration.</p></div><button class="secondary" onclick={() => load()}>Refresh status</button></header>
<WorkshopNav {id} />
{#if error}<p class="error" role="alert">{error}</p>{/if}
{#if notice}<p class="notice" role="status">{notice}</p>{/if}

<section class="grid modules" aria-label="Optional modules">
	{#each modules as module (module.key)}
		{@const missing = missingDependencies(module)}
		<article class="card stack">
			<div class="row"><div><h2>{module.name}</h2></div><StatusBadge state={module.state} /></div>
			<p class="muted module-description">{module.description}</p>
			{#if module.error}<p class="error">{sentence(module.error)}</p>{/if}
			{#if !module.entitled}<p class="muted dependency">This capability is not included in the workshop’s active signed entitlement.</p>{/if}
			{#if !module.release_available}<p class="muted dependency">The workshop’s active application release does not provide this capability.</p>{/if}
			{#if module.state === 'available' || module.state === 'failed'}
				<button disabled={!module.can_manage || busy === module.key || missing.length > 0} onclick={() => enable(module)}>{busy === module.key ? 'Queuing…' : module.state === 'failed' ? 'Retry installation' : 'Enable module'}</button>
				{#if missing.length > 0}<p class="muted dependency">Enable {missing.map(moduleName).join(', ')} first.</p>{/if}
			{:else if ['requested', 'installing'].includes(module.state) && module.operation_id}
				<OperationCard id={module.operation_id} compact onsettled={load} />
			{:else if ['requested', 'installing'].includes(module.state)}
				<p class="muted">Installation is queued.</p>
			{:else if module.state === 'restricting' && module.operation_id}
				<p class="muted">Access is blocked while downstream restriction evidence is verified.</p>
				<OperationCard id={module.operation_id} compact onsettled={load} />
			{:else if module.state === 'restricting'}
				<p class="error">Access is blocked, but downstream enforcement needs operator attention.</p>
			{:else if module.state === 'unavailable'}
				<p class="muted">Upgrade this workshop to a compatible application release before enabling it.</p>
			{:else if module.state === 'restricted'}
				<p class="muted">Installed data is retained, but processing is disabled until entitlement is restored.</p>
			{:else}
				<p class="notice">Ready for this workshop.</p>
			{/if}
		</article>
	{/each}
</section>

<aside class="card section"><h2>Core services</h2><p class="muted">Identity, Odoo, and French accounting are part of every workshop. Documents, invoice capture, and Azure extraction are optional and must be enabled in dependency order.</p></aside>

<style>
	.modules{grid-template-columns:repeat(auto-fit,minmax(280px,1fr));align-items:start}.module-description{min-height:3rem;margin:0}.dependency{font-size:.85rem;margin:0}.modules h2{font-family:inherit;font-size:1.05rem;margin:0}
</style>
