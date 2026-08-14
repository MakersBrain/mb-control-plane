<script lang="ts">
	import StatusBadge from '$lib/components/StatusBadge.svelte';
	import { formatInstant, sentence } from '$lib/format';
	import { download, request } from '$lib/session.svelte';
	import type { PrivacyRequestResponse } from '$lib/generated/control-api';

	let requests = $state<PrivacyRequestResponse[]>([]);
	let requestType = $state('access');
	let busy = $state(false);
	let error = $state('');
	let notice = $state('');
	$effect(() => { void load(); });

	async function load() {
		try { requests = await request<PrivacyRequestResponse[]>('/v1/privacy/requests'); error = ''; }
		catch (cause) { error = cause instanceof Error ? cause.message : String(cause); }
	}

	async function createRequest() {
		busy = true; error = ''; notice = '';
		try {
			await request('/v1/privacy/requests', { method: 'POST', headers: { 'idempotency-key': crypto.randomUUID() }, body: JSON.stringify({ request_type: requestType, workshop_ids: [] }) });
			notice = 'Your request was recorded. A privacy reviewer must assess it before processing.';
			await load();
		} catch (cause) { error = cause instanceof Error ? cause.message : String(cause); }
		finally { busy = false; }
	}

	async function saveExport(item: PrivacyRequestResponse) {
		busy = true; error = ''; notice = '';
		try {
			const result = await download(`/v1/privacy/requests/${item.id}/export`);
			const url = URL.createObjectURL(result.blob);
			const anchor = document.createElement('a'); anchor.href = url; anchor.download = result.filename; anchor.click();
			URL.revokeObjectURL(url);
			notice = 'The encrypted export was redeemed. This download link cannot be used again.';
			await load();
		} catch (cause) { error = cause instanceof Error ? cause.message : String(cause); }
		finally { busy = false; }
	}
</script>

<svelte:head><title>Your privacy · MakersBrain</title><meta name="description" content="Exercise your GDPR rights and retrieve approved data exports." /></svelte:head>

<header class="page-header"><div><p class="eyebrow">Privacy centre</p><h1>Your privacy rights</h1><p class="muted">Submit a rights request and follow its review. Exports are encrypted at rest and downloadable once for seven days.</p></div></header>
{#if error}<p class="error" role="alert">{error}</p>{/if}{#if notice}<p class="notice" role="status">{notice}</p>{/if}

<section class="section card">
	<div class="section-header"><div><h2>New request</h2><p class="muted">Requests cover your MakersBrain control account. Processor evidence is included only after every scoped processor acknowledges completion.</p></div></div>
	<form class="form rights-form" onsubmit={(event) => { event.preventDefault(); void createRequest(); }}>
		<label>Right to exercise<select bind:value={requestType}><option value="access">Access</option><option value="portability">Data portability</option><option value="rectification">Rectification</option><option value="erasure">Erasure</option><option value="restriction">Restriction</option><option value="objection">Objection</option></select></label>
		<div class="form-actions"><button disabled={busy}>{busy ? 'Submitting…' : 'Submit request'}</button></div>
	</form>
</section>

<section class="section"><div class="section-header"><h2>Your requests</h2></div><div class="card table-wrap">
	{#if requests.length === 0}<div class="empty">No privacy request has been submitted.</div>{:else}<table><thead><tr><th>Submitted</th><th>Right</th><th>Deadline</th><th>Status</th><th>Export</th></tr></thead><tbody>{#each requests as item}<tr><td>{formatInstant(item.requested_at)}</td><td>{sentence(item.request_type)}</td><td>{formatInstant(item.extended_due_at ?? item.due_at)}</td><td><StatusBadge state={item.status} /></td><td>{#if item.export?.state === 'ready'}<button disabled={busy} onclick={() => saveExport(item)}>Download once</button><div class="muted">Expires {formatInstant(item.export.expires_at)}</div>{:else if item.export}<StatusBadge state={item.export.state} />{:else}<span class="muted">Not ready</span>{/if}</td></tr>{/each}</tbody></table>{/if}
</div></section>

<style>.rights-form{grid-template-columns:minmax(15rem,24rem) auto;align-items:end}.form-actions{padding-bottom:.1rem}@media(max-width:700px){.rights-form{grid-template-columns:1fr}}</style>
