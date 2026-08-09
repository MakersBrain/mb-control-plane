<script lang="ts">
	import OperationCard from '$lib/components/OperationCard.svelte';
	import StatusBadge from '$lib/components/StatusBadge.svelte';
	import { roleLabel } from '$lib/format';
	import { request } from '$lib/session.svelte';
	import type { WorkshopSummary } from '$lib/types';

	let workshops = $state<WorkshopSummary[]>([]);
	let error = $state('');
	let loading = $state(true);
	let creating = $state(false);
	let operationId = $state('');
	let createdWorkshopId = $state('');
	let createKey = crypto.randomUUID();
	let form = $state({ slug: '', display_name: '', country_code: 'FR', time_zone: 'Europe/Paris' });

	$effect(() => { void load(); });

	async function load() {
		try {
			workshops = await request<WorkshopSummary[]>('/v1/workshops');
			error = '';
		} catch (cause) {
			error = cause instanceof Error ? cause.message : String(cause);
		} finally {
			loading = false;
		}
	}

	async function create() {
		creating = true;
		error = '';
		try {
			const result = await request<{ id: string; operation_id: string }>('/v1/workshops', {
				method: 'POST',
				headers: { 'idempotency-key': createKey },
				body: JSON.stringify({ ...form, slug: form.slug.trim().toLowerCase(), display_name: form.display_name.trim() })
			});
			createdWorkshopId = result.id;
			operationId = result.operation_id;
			createKey = crypto.randomUUID();
			form = { slug: '', display_name: '', country_code: 'FR', time_zone: 'Europe/Paris' };
			await load();
		} catch (cause) {
			error = cause instanceof Error ? cause.message : String(cause);
		} finally {
			creating = false;
		}
	}
</script>

<svelte:head><title>Your workshops · MakersBrain</title><meta name="description" content="Manage your MakersBrain workshops, people and services." /></svelte:head>

<header class="page-header">
	<div><p class="eyebrow">Control centre</p><h1>Your workshops</h1><p class="muted">People, access, modules, service health, and recovery.</p></div>
	<a class="button secondary" href="#new-workshop">Create a workshop</a>
</header>

{#if error}<p class="error" role="alert">{error}</p>{/if}
{#if operationId}
	<section class="section" aria-labelledby="provisioning-title">
		<div class="section-header"><div><h2 id="provisioning-title">Preparing your workshop</h2><p class="muted">You can leave this page; provisioning continues safely.</p></div><a class="button secondary" href={`/operations/${operationId}`}>Full details</a></div>
		<OperationCard id={operationId} onsettled={load} />
		{#if createdWorkshopId}<p><a href={`/workshops/${createdWorkshopId}/members`}>Open the workshop control centre →</a></p>{/if}
	</section>
{/if}

<section class="section" aria-labelledby="workshop-list-title">
	<div class="section-header"><h2 id="workshop-list-title">Workshops</h2><span class="muted">{workshops.length} available</span></div>
	{#if loading}
		<div class="card empty"><span class="spinner" aria-hidden="true"></span><p>Loading workshops…</p></div>
	{:else if workshops.length === 0}
		<div class="card empty"><h3>No workshops yet</h3><p>Create your first workshop below. Its Odoo service and identity access will be provisioned in the background.</p></div>
	{:else}
		<div class="grid workshops">
			{#each workshops as workshop (workshop.id)}
				<a class="card workshop-card" href={`/workshops/${workshop.id}/members`}>
					<div class="row"><strong>{workshop.display_name}</strong><span class="arrow" aria-hidden="true">→</span></div>
					<div><span class="muted">{workshop.slug}</span><div class="target-grid"><StatusBadge state={workshop.status} /><span class="badge">{roleLabel(workshop.role)}</span><span class="badge">{workshop.plan}</span></div></div>
				</a>
			{/each}
		</div>
	{/if}
</section>

<section class="section card" id="new-workshop" aria-labelledby="new-workshop-title">
	<div class="section-header"><div><h2 id="new-workshop-title">Create a workshop</h2><p class="muted">The address is permanent. MakersBrain creates its isolated database and makes you the first owner.</p></div></div>
	<form class="form create-form" onsubmit={(event) => { event.preventDefault(); void create(); }}>
		<label>Workshop name<input bind:value={form.display_name} autocomplete="organization" maxlength="120" required placeholder="Atelier des Terres" /></label>
		<label>Permanent address<input bind:value={form.slug} pattern={'[a-z0-9][a-z0-9-]{1,62}[a-z0-9]'} maxlength="64" required placeholder="atelier-des-terres" /><span class="muted hint">Lower-case letters, numbers and hyphens.</span></label>
		<label>Country<select bind:value={form.country_code}><option value="FR">France</option></select></label>
		<label>Time zone<input bind:value={form.time_zone} required /></label>
		<div class="form-actions"><button disabled={creating}>{creating ? 'Creating…' : 'Create and provision'}</button></div>
	</form>
</section>

<style>
	.create-form{grid-template-columns:repeat(2,minmax(0,1fr))}.form-actions{grid-column:1/-1}.hint{font-size:.78rem;font-weight:400}@media(max-width:700px){.create-form{grid-template-columns:1fr}.form-actions{grid-column:auto}}
</style>
