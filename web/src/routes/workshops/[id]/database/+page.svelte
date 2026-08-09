<script lang="ts">
	import { page } from '$app/state';
	import { request } from '$lib/session.svelte';

	const id = $derived(page.params.id ?? '');
	let workshop = $state<any>();
	let database = $state<any>();
	let error = $state('');
	let notice = $state('');
	let busy = $state(false);
	let recoveryLabel = $state('');
	let duplicateLabel = $state('Test copy');
	let duplicateConfirmation = $state('');
	let restoreConfirmation = $state('');

	$effect(() => {
		id;
		void load();
		const timer = window.setInterval(() => void load(false), 4000);
		return () => window.clearInterval(timer);
	});

	async function load(showError = true) {
		try {
			[workshop, database] = await Promise.all([
				request<any>(`/v1/workshops/${id}`),
				request<any>(`/v1/workshops/${id}/database`)
			]);
			if (showError) error = '';
		} catch (e) {
			if (showError) error = String(e);
		}
	}

	async function start(path: string, body: unknown, message: string) {
		busy = true; error = ''; notice = '';
		try {
			await request(`/v1/workshops/${id}/database/${path}`, {
				method: 'POST',
				headers: { 'idempotency-key': crypto.randomUUID() },
				body: JSON.stringify(body)
			});
			notice = message;
			await load();
		} catch (e) { error = String(e); }
		finally { busy = false; }
	}

	const makeRecovery = (kind: 'snapshots' | 'backups') => start(kind, { label: recoveryLabel || undefined }, kind === 'snapshots' ? 'Snapshot queued.' : 'Portable backup queued.');
	async function restore(point: any) {
		await start('restores', { recovery_point_id: point.id, confirmation: restoreConfirmation }, 'Restore queued. A verified S3 safety backup will be created first.');
		restoreConfirmation = '';
	}
	async function duplicate() {
		await start('duplicates', { label: duplicateLabel, confirmation: duplicateConfirmation }, 'Non-routable duplicate queued.');
		duplicateConfirmation = '';
	}
	const when = (value?: string) => value ? new Date(value).toLocaleString() : '—';
	const size = (value?: number) => value == null ? '—' : `${(value / 1048576).toFixed(1)} MB`;
	const workshopUrl = (hostname: string) => hostname.endsWith('.localhost') ? `http://${hostname}:8169` : `https://${hostname}`;
</script>

<svelte:head><title>{workshop?.display_name || 'Database'} · MakersBrain</title></svelte:head>
<p><a href={`/workshops/${id}/members`}>← Workshop</a></p>
<div class="row"><div><h1>Workshop recovery</h1><p class="muted">Consistent recovery points for Odoo and active document services.</p></div>{#if database?.primary}<span class="status">{database.primary.state}</span>{/if}</div>
{#if error}<p class="error">{error}</p>{/if}
{#if notice}<p class="notice">{notice}</p>{/if}

{#if database?.primary}
	<section class="card stack">
		<div><strong>Workshop address</strong><div><a href={workshopUrl(database.primary.public_hostname)}>{database.primary.public_hostname}</a></div></div>
		<p class="muted">The public address is based on the workshop slug. The physical database has a separate opaque identifier and is never exposed here.</p>
		<div class="facts"><div><span class="muted">Created</span><strong>{when(database.primary.created_at)}</strong></div><div><span class="muted">Last restored</span><strong>{when(database.primary.last_restored_at)}</strong></div></div>
	</section>
{:else}<p class="card muted">The Odoo database is still being provisioned.</p>{/if}

{#if database?.can_manage}
	<section class="grid database-actions">
		<form class="card form" onsubmit={(event) => { event.preventDefault(); void makeRecovery('snapshots'); }}>
			<h2>Create recovery point</h2><p class="muted">Snapshots stay local. Portable backups are encrypted, verified and retained in S3. Paperless is included whenever Documents is active.</p>
			<label>Optional label<input bind:value={recoveryLabel} maxlength="120" placeholder="Before stock import" /></label>
			<div class="actions"><button disabled={busy}>Create snapshot</button><button class="secondary" type="button" disabled={busy} onclick={() => void makeRecovery('backups')}>Create backup</button></div>
		</form>
		<form class="card form" onsubmit={(event) => { event.preventDefault(); void duplicate(); }}>
			<h2>Duplicate database</h2><p class="muted">Creates an isolated copy with no public hostname. It cannot receive customer traffic.</p>
			<label>Copy label<input bind:value={duplicateLabel} maxlength="120" required /></label>
			<label>Type <code>{workshop?.slug}</code> to confirm<input bind:value={duplicateConfirmation} required /></label>
			<button class="danger" disabled={busy || duplicateConfirmation !== workshop?.slug}>Create isolated copy</button>
		</form>
	</section>
{/if}

<section class="stack"><h2>Recovery points</h2>
	{#if !database?.recovery_points?.length}<p class="card muted">No snapshots or backups yet.</p>{/if}
	{#each database?.recovery_points || [] as point}
		<article class="card recovery-row"><div><strong>{point.label}</strong><div class="muted">{point.kind} · {(point.component_scope || ['odoo']).join(' + ')} · {point.storage_location} · {when(point.created_at)} · {size(point.size_bytes)}</div>{#if point.expires_at}<div class="muted">Retained until {when(point.expires_at)}</div>{/if}</div><span class="status">{point.operation_state || point.state}{point.verified_at ? ' · verified' : ''}</span>
			{#if database.can_manage && point.state === 'ready' && point.verified_at}<div class="restore"><label>Type <code>{workshop.slug}</code> to restore<input bind:value={restoreConfirmation} /></label><button class="danger" disabled={busy || restoreConfirmation !== workshop.slug} onclick={() => void restore(point)}>Restore complete workshop</button></div>{/if}
		</article>
	{/each}
</section>

<section class="stack"><h2>Isolated copies</h2>
	{#if !database?.duplicates?.length}<p class="card muted">No database copies.</p>{/if}
	{#each database?.duplicates || [] as copy}<article class="card row"><div><strong>{copy.label}</strong><div class="muted">Created {when(copy.created_at)} · never publicly routable</div></div><span class="status">{copy.state}</span></article>{/each}
</section>
