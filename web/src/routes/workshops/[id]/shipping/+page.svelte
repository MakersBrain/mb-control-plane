<script lang="ts">
	import { page } from '$app/state';
	import WorkshopNav from '$lib/components/WorkshopNav.svelte';
	import StatusBadge from '$lib/components/StatusBadge.svelte';
	import { request } from '$lib/session.svelte';
	import type { WorkshopSummary } from '$lib/types';
	import type { CarrierSecretResponse, CarrierTarget } from '$lib/generated/control-api';

	const id = $derived(page.params.id ?? '');
	let workshop = $state<WorkshopSummary>();
	let targets = $state<CarrierTarget[]>([]);
	let secrets = $state<CarrierSecretResponse[]>([]);
	let selected = $state('');
	let accessKey = $state('');
	let secretKey = $state('');
	let webhookSecret = $state('');
	let error = $state('');
	let notice = $state('');
	let busy = $state(false);
	const target = $derived(targets.find((item) => String(item.carrier_id) === selected));

	$effect(() => { id; void load(); });

	async function load() {
		try {
			[workshop, targets, secrets] = await Promise.all([
				request<WorkshopSummary>(`/v1/workshops/${id}`),
				request<CarrierTarget[]>(`/v1/workshops/${id}/carrier-targets`).catch(() => []),
				request<CarrierSecretResponse[]>(`/v1/workshops/${id}/carrier-secrets`)
			]);
			if (!selected && targets.length) selected = String(targets[0].carrier_id);
			error = '';
		} catch (cause) { error = cause instanceof Error ? cause.message : String(cause); }
	}

	async function save() {
		if (!target) return;
		busy = true; error = ''; notice = '';
		try {
			const credentials = target.provider === 'sendcloud'
				? { public_key: accessKey, private_key: secretKey, ...(webhookSecret ? { webhook_signature_key: webhookSecret } : {}) }
				: { access_key: accessKey, secret_key: secretKey, webhook_secret: webhookSecret };
			await request(`/v1/workshops/${id}/carrier-secrets`, {
				method: 'POST',
				headers: { 'idempotency-key': crypto.randomUUID() },
				body: JSON.stringify({ provider: target.provider, environment: target.environment, company_id: target.company_id, carrier_id: target.carrier_id, credentials })
			});
			accessKey = ''; secretKey = ''; webhookSecret = '';
			notice = target.provider === 'sendcloud'
				? 'Credentials stored outside Odoo and bound to this carrier. Use Test connection for API access, then send a signed Sendcloud Test API Webhook to verify webhook readiness.'
				: 'Credentials stored outside Odoo and bound to this carrier. Use Test connection in Odoo to verify provider access and webhook readiness.';
			await load();
		} catch (cause) { error = cause instanceof Error ? cause.message : String(cause); }
		finally { busy = false; }
	}

	async function remove(secret: CarrierSecretResponse) {
		if (!window.confirm('Delete this external carrier credential? Label purchases will stop until new credentials are saved.')) return;
		busy = true; error = ''; notice = '';
		try {
			await request(`/v1/workshops/${id}/carrier-secrets/${secret.id}`, { method: 'DELETE', headers: { 'idempotency-key': crypto.randomUUID() } });
			notice = 'The external credential was deleted. Historical shipments remain readable.';
			await load();
		} catch (cause) { error = cause instanceof Error ? cause.message : String(cause); }
		finally { busy = false; }
	}
</script>

<svelte:head><title>Shipping · {workshop?.display_name || 'MakersBrain'}</title></svelte:head>
<p><a href="/">← Workshops</a></p>
<header class="page-header"><div><p class="eyebrow">{workshop?.display_name ?? 'Workshop'}</p><h1>Shipping credentials</h1><p class="muted">Store one provider credential set per Odoo carrier. Secret values are accepted once and never displayed again.</p></div><button class="secondary" onclick={load}>Refresh</button></header>
<WorkshopNav {id} />
{#if error}<p class="error" role="alert">{error}</p>{/if}
{#if notice}<p class="notice" role="status">{notice}</p>{/if}

{#if targets.length === 0}
	<section class="card"><h2>No supported carrier found</h2><p class="muted">Enable Boxtal or Sendcloud Shipping, then create its Odoo delivery method before entering credentials here.</p></section>
{:else}
	<section class="card stack credentials">
		<h2>Add or rotate credentials</h2>
		<label>Odoo carrier<select bind:value={selected}>{#each targets as item}<option value={String(item.carrier_id)}>{item.carrier_name} · {item.company_name} · {item.environment}</option>{/each}</select></label>
		<label>{target?.provider === 'sendcloud' ? 'Public API key' : 'Application access key'}<input autocomplete="off" bind:value={accessKey} /></label>
		<label>{target?.provider === 'sendcloud' ? 'Private API key' : 'Application secret key'}<input type="password" autocomplete="new-password" bind:value={secretKey} /></label>
		<label>{target?.provider === 'sendcloud' ? 'Webhook Signature Key (only when Sendcloud supplies a separate key)' : 'Webhook validation secret'}<input type="password" autocomplete="new-password" bind:value={webhookSecret} /></label>
		<button disabled={busy || !target || accessKey.length < 8 || secretKey.length < (target?.provider === 'sendcloud' ? 16 : 24) || (target?.provider !== 'sendcloud' && webhookSecret.length < 24) || (target?.provider === 'sendcloud' && webhookSecret.length > 0 && webhookSecret.length < 16)} onclick={save}>{busy ? 'Saving…' : 'Save credentials'}</button>
		<p class="muted">Saving again rotates to a new opaque reference after Odoo accepts the replacement. Test and production applications must use separate Odoo carriers.</p>
	</section>
{/if}

<section class="section"><div class="section-header"><div><h2>Configured carriers</h2><p class="muted">Only references and lifecycle state are shown.</p></div></div>
	{#if secrets.length === 0}<p class="card muted">No carrier credentials are stored.</p>{/if}
	{#each secrets as secret (secret.id)}
		<article class="card row"><div><strong>{targets.find((item) => item.carrier_id === secret.carrier_id)?.carrier_name ?? `Carrier ${secret.carrier_id}`}</strong><div class="muted">{secret.provider} · {secret.environment} · version {secret.version}</div></div><div class="actions"><StatusBadge state={secret.state} /><button class="danger" disabled={busy} onclick={() => remove(secret)}>Delete</button></div></article>
	{/each}
</section>

<style>.credentials{max-width:44rem}.actions{display:flex;align-items:center;gap:.75rem}</style>
