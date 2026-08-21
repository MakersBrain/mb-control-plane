<script lang="ts">
	import { page } from '$app/state';
	import OperatorGuard from '$lib/components/OperatorGuard.svelte';
	import PlatformNav from '$lib/components/PlatformNav.svelte';
	import StatusBadge from '$lib/components/StatusBadge.svelte';
	import { formatInstant } from '$lib/format';
	import { request } from '$lib/session.svelte';
	import type { ApplicationReleaseDetailResponse,TenantReleaseAdoptionResponse } from '$lib/generated/control-api';
	let release = $state<ApplicationReleaseDetailResponse>(), tenants = $state<TenantReleaseAdoptionResponse[]>([]), error = $state(''), busy = $state(false), confirmation = $state('');
	const id = $derived(page.params.id);
	$effect(() => { void load(); });
	async function load() { try { [release, tenants] = await Promise.all([request<ApplicationReleaseDetailResponse>(`/v1/platform/releases/${id}`), request<TenantReleaseAdoptionResponse[]>(`/v1/platform/releases/${id}/tenants`)]); error = ''; } catch (cause) { error = cause instanceof Error ? cause.message : String(cause); } }
	async function mutate(action: 'preflight' | 'adopt') { if (!release) return; busy = true; error = ''; try { await request(`/v1/platform/releases/${id}/${action}`, { method: 'POST', headers: { 'idempotency-key': crypto.randomUUID(), 'if-match': `"release-${id}-v${release.version}"` }, body: action === 'adopt' ? JSON.stringify({ confirmation }) : undefined }); await load(); } catch (cause) { error = cause instanceof Error ? cause.message : String(cause); } finally { busy = false; } }
</script>

<svelte:head><title>{id} · Releases · MakersBrain</title></svelte:head>
<OperatorGuard>
	<header class="page-header"><div><p class="eyebrow">Application release</p><h1>{id}</h1><p class="muted">Digest-bound artifact, compatibility and per-tenant adoption evidence.</p></div><a class="button secondary" href="/platform/releases">All releases</a></header>
	<PlatformNav />
	{#if error}<p class="error" role="alert">{error}</p>{/if}
	{#if release}
		<section class="grid summary"><article class="card"><span class="muted">State</span><div><StatusBadge state={release.status} /></div></article><article class="card"><span class="muted">Change class</span><strong>{release.change_class}</strong></article><article class="card"><span class="muted">Schema epoch</span><strong>{release.schema_epoch}</strong></article><article class="card"><span class="muted">Published</span><strong>{formatInstant(release.published_at)}</strong></article></section>
		<section class="card evidence"><div><span class="muted">Odoo subject</span><code>{release.odoo_subject_digest}</code></div><div><span class="muted">Extension subject</span><code>{release.extension_subject_digest}</code></div><div><span class="muted">Release manifest</span><code>{release.manifest_digest}</code></div><div><span class="muted">Source commit</span><code>{release.source_commit}</code></div></section>
		{#if release.status === 'candidate'}<section class="card action"><div><h2>Preflight release</h2><p class="muted">Validate compatibility and freeze the fleet inventory. This does not route candidate code.</p></div><button disabled={busy} onclick={() => mutate('preflight')}>Run preflight</button></section>{/if}
		{#if release.status === 'prepared'}<section class="card action danger-zone"><div><h2>Adopt across the fleet</h2><p class="muted">Each tenant is isolated and backed up before upgrade. Enter the exact release ID to confirm.</p><input bind:value={confirmation} aria-label="Release confirmation" placeholder={id} autocomplete="off" /></div><button disabled={busy || confirmation !== id} onclick={() => mutate('adopt')}>Adopt release</button></section>{/if}
		<section class="section"><div class="section-header"><div><h2>Tenant adoption</h2><p class="muted">Recovery references are opaque; credentials and provider payloads are never displayed.</p></div></div><div class="card table-wrap">{#if tenants.length === 0}<div class="empty">No tenant adoption has started.</div>{:else}<table><thead><tr><th>Workshop</th><th>State</th><th>Source</th><th>Recovery</th><th>Updated</th></tr></thead><tbody>{#each tenants as tenant (tenant.database_id)}<tr><td>{tenant.workshop_name}</td><td><StatusBadge state={tenant.state} /></td><td>{tenant.source_release_id ?? 'Initial release'}</td><td>{tenant.backup_recovery_id ?? 'Pending'}</td><td>{formatInstant(tenant.updated_at)}</td></tr>{/each}</tbody></table>{/if}</div></section>
	{/if}
</OperatorGuard>

<style>.summary{grid-template-columns:repeat(4,minmax(0,1fr));margin-bottom:1rem}.summary article{display:grid;gap:.4rem}.evidence{display:grid;gap:.8rem}.evidence div{display:grid;gap:.25rem}.evidence code{overflow-wrap:anywhere}.action{margin-top:1rem;display:flex;align-items:end;justify-content:space-between;gap:1rem}.action h2{margin:0}.action input{width:min(34rem,100%)}@media(max-width:760px){.summary{grid-template-columns:1fr 1fr}.action{align-items:stretch;flex-direction:column}}</style>
