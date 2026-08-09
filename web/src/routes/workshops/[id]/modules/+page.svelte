<script lang="ts">
	import { page } from '$app/state';
	import { request } from '$lib/session.svelte';

	const id = $derived(page.params.id ?? '');
	let workshop = $state<any>();
	let modules = $state<any[]>([]);
	let error = $state('');
	let busy = $state('');

	$effect(() => { id; void load(); });

	async function load() {
		try {
			[workshop, modules] = await Promise.all([
				request<any>(`/v1/workshops/${id}`),
				request<any[]>(`/v1/workshops/${id}/modules`)
			]);
		} catch (cause) {
			error = String(cause);
		}
	}

	async function enable(moduleKey: string) {
		busy = moduleKey;
		error = '';
		try {
			await request(`/v1/workshops/${id}/modules/${moduleKey}/enable`, {
				method: 'POST',
				headers: { 'idempotency-key': crypto.randomUUID() }
			});
			await load();
		} catch (cause) {
			error = String(cause);
		} finally {
			busy = '';
		}
	}

	function missingDependencies(module: any) {
		return (module.dependencies || []).filter((key: string) =>
			!modules.some((candidate) => candidate.key === key && candidate.state === 'enabled')
		);
	}

	function moduleName(key: string) {
		return modules.find((module) => module.key === key)?.name || key;
	}
</script>

<svelte:head><title>Modules · {workshop?.display_name || 'MakersBrain'}</title></svelte:head>

<p><a href={`/workshops/${id}/members`}>← Workshop</a></p>
<div class="row">
	<div><h1>Modules</h1><p class="muted">Enable supported features for this workshop. Dependencies are installed automatically.</p></div>
	<button class="secondary" onclick={load}>Refresh status</button>
</div>
{#if error}<p class="error">{error}</p>{/if}

<section class="grid">
	{#each modules as module}
		<article class="card stack">
			<div class="row">
				<strong>{module.name}</strong>
				<span class:degraded={module.state === 'failed'} class="status">{module.state}</span>
			</div>
			<p class="muted">{module.description}</p>
			{#if module.state === 'available' || module.state === 'failed'}
				{@const missing = missingDependencies(module)}
				<button disabled={!module.can_manage || busy === module.key || missing.length > 0} onclick={() => enable(module.key)}>
					{busy === module.key ? 'Enabling…' : module.state === 'failed' ? 'Retry' : 'Enable'}
				</button>
				{#if missing.length > 0}
					<p class="muted">Requires {missing.map(moduleName).join(', ')}.</p>
				{/if}
			{:else if module.state === 'requested'}
				<p class="muted">Installation is queued. Refresh to update its state.</p>
			{:else}
				<p>Enabled</p>
			{/if}
		</article>
	{/each}
</section>

<aside class="card" style="margin-top:1rem">
	<strong>Core services</strong>
	<p class="muted">Identity, Odoo, and French accounting are always enabled. Documents, invoice capture, and Azure extraction are optional.</p>
</aside>
