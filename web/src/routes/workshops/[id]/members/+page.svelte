<script lang="ts">
	import { page } from '$app/state';
	import OperationCard from '$lib/components/OperationCard.svelte';
	import StatusBadge from '$lib/components/StatusBadge.svelte';
	import WorkshopNav from '$lib/components/WorkshopNav.svelte';
	import { formatInstant, isPending, roleLabel, sentence } from '$lib/format';
	import { request, session } from '$lib/session.svelte';
	import type { Integration, Invitation, Member, OwnershipTransfer, WorkshopRole, WorkshopSummary } from '$lib/types';

	const id = $derived(page.params.id ?? '');
	let workshop = $state<WorkshopSummary>();
	let members = $state<Member[]>([]);
	let integrations = $state<Integration[]>([]);
	let invitations = $state<Invitation[]>([]);
	let transfers = $state<OwnershipTransfer[]>([]);
	let error = $state('');
	let notice = $state('');
	let busy = $state('');
	let inviteKey = crypto.randomUUID();
	let invite = $state<{ email: string; role: Exclude<WorkshopRole, 'owner'>; locale: string }>({ email: '', role: 'artisan', locale: 'en' });
	const canManage = $derived(workshop?.role === 'owner' || workshop?.role === 'studio_manager');
	const canTransfer = $derived(workshop?.role === 'owner');
	const needsPolling = $derived(members.some((member) => isPending(member.operation_state) || Object.values(member.targets).some((target) => target.state === 'pending')) || integrations.some((item) => item.health === 'provisioning'));

	$effect(() => {
		id;
		void load();
		const timer = window.setInterval(() => { if (needsPolling) void load(false); }, 4000);
		return () => window.clearInterval(timer);
	});

	const key = () => crypto.randomUUID();
	async function load(showError = true) {
		try {
			[workshop, members, integrations] = await Promise.all([
				request<WorkshopSummary>(`/v1/workshops/${id}`),
				request<Member[]>(`/v1/workshops/${id}/members`),
				request<Integration[]>(`/v1/workshops/${id}/integrations`)
			]);
			if (workshop.role === 'owner' || workshop.role === 'studio_manager') invitations = await request<Invitation[]>(`/v1/workshops/${id}/invitations`);
			else invitations = [];
			transfers = await request<OwnershipTransfer[]>(`/v1/workshops/${id}/ownership-transfers`);
			if (showError) error = '';
		} catch (cause) {
			if (showError) error = cause instanceof Error ? cause.message : String(cause);
		}
	}

	async function act(name: string, action: () => Promise<unknown>, success: string) {
		busy = name; error = ''; notice = '';
		try { await action(); notice = success; await load(); }
		catch (cause) { error = cause instanceof Error ? cause.message : String(cause); await load(false); }
		finally { busy = ''; }
	}

	async function sendInvite() {
		await act('invite', () => request(`/v1/workshops/${id}/invitations`, { method: 'POST', headers: { 'idempotency-key': inviteKey }, body: JSON.stringify(invite) }), `Invitation sent to ${invite.email.trim().toLowerCase()}.`);
		if (!error) { invite.email = ''; inviteKey = crypto.randomUUID(); }
	}
	const resend = (invitationId: string) => act(`invite-${invitationId}`, () => request(`/v1/invitations/${invitationId}/resend`, { method: 'POST', headers: { 'idempotency-key': key() } }), 'A new single-use invitation link was sent.');
	async function revoke(invitationId: string) { if (confirm('Revoke this invitation? Its link will stop working immediately.')) await act(`invite-${invitationId}`, () => request(`/v1/invitations/${invitationId}`, { method: 'DELETE', headers: { 'idempotency-key': key() } }), 'Invitation revoked.'); }
	const changeRole = (member: Member, role: string) => act(`member-${member.id}`, () => request(`/v1/workshops/${id}/members/${member.id}`, { method: 'PATCH', headers: { 'idempotency-key': key(), 'if-match': member.etag }, body: JSON.stringify({ role }) }), 'Role update queued for reconciliation.');
	async function remove(member: Member) { if (confirm('Remove this person? Control-plane access is revoked immediately and connected services will converge in the background.')) await act(`member-${member.id}`, () => request(`/v1/workshops/${id}/members/${member.id}`, { method: 'DELETE', headers: { 'idempotency-key': key(), 'if-match': member.etag } }), 'Member removed; downstream access revocation is in progress.'); }
	async function transfer(user: string) { if (confirm('Ask this person to become the owner? You will become a studio manager only after they accept.') && workshop) await act(`member-${user}`, () => request(`/v1/workshops/${id}/ownership-transfers`, { method: 'POST', headers: { 'idempotency-key': key(), 'if-match': `"workshop-${id}-v${workshop?.version}"` }, body: JSON.stringify({ to_user_id: user }) }), 'Ownership transfer requested.'); }
	const acceptTransfer = (transfer: OwnershipTransfer) => act(`transfer-${transfer.id}`, () => request(`/v1/ownership-transfers/${transfer.id}/accept`, { method: 'POST', headers: { 'idempotency-key': key(), 'if-match': transfer.etag } }), 'Ownership transferred. Both accounts are being reconciled.');
	const integrationReady = (integration: Integration) => integration.health === 'ready' && integration.applied_epoch >= integration.desired_epoch;
	function lastReconciliation(member: Member): string {
		const observed = Object.values(member.targets).map((target) => target.observed_at).filter((value): value is string => !!value).sort();
		return observed.length ? formatInstant(observed.at(-1)) : 'Not observed yet';
	}
</script>

<svelte:head><title>{workshop?.display_name || 'People & access'} · MakersBrain</title></svelte:head>
<p><a href="/">← Workshops</a></p>
<header class="page-header">
	<div><p class="eyebrow">Workshop control centre</p><h1>{workshop?.display_name ?? 'People & access'}</h1><p class="muted">Your role: {roleLabel(workshop?.role ?? '')}</p></div>
	{#if workshop}<div class="actions"><StatusBadge state={workshop.status} /><span class="badge">{workshop.plan}</span></div>{/if}
</header>
<WorkshopNav {id} />
{#if error}<p class="error" role="alert">{error}</p>{/if}
{#if notice}<p class="notice" role="status">{notice}</p>{/if}

{#each transfers as transfer (transfer.id)}
	{#if transfer.can_accept}
		<aside class="card row transfer"><div><strong>Ownership transfer waiting for you</strong><div class="muted">Accept before {formatInstant(transfer.expires_at)}. The current owner keeps ownership until you do.</div></div><button disabled={busy === `transfer-${transfer.id}`} onclick={() => acceptTransfer(transfer)}>{busy === `transfer-${transfer.id}` ? 'Accepting…' : 'Accept ownership'}</button></aside>
	{/if}
{/each}

<section class="section" aria-labelledby="members-title">
	<div class="section-header"><div><h2 id="members-title">People & access</h2><p class="muted">Public roles are reconciled to identity, Odoo, and Documents without exposing raw groups.</p></div><span class="muted">{members.length} member{members.length === 1 ? '' : 's'}</span></div>
	<div class="stack">
		{#each members as member (member.id)}
			<article class="card member">
				<div><div class="actions"><strong>{member.display_name || member.email}</strong>{#if member.id === session.me?.id}<span class="badge">You</span>{/if}<StatusBadge state={member.status} /></div><div class="muted">{member.email}</div><div class="muted reconciliation">Last reconciliation: {lastReconciliation(member)}</div>
					<div class="target-grid" aria-label="Connected access targets">
						{#each Object.entries(member.targets || {}) as [target, value]}
							<span class:degraded={value.state === 'degraded'} class="target" title={value.error ? sentence(value.error) : `${value.applied_epoch}/${value.desired_epoch} applied`}>{sentence(target)}: {value.state === 'ready' && value.applied_epoch >= value.desired_epoch ? 'ready' : sentence(value.state)}{value.error ? ` · ${sentence(value.error)}` : ''}</span>
						{/each}
					</div>
				</div>
				<label><span class="visually-hidden">Role for {member.email}</span><select value={member.role} disabled={!canManage || member.role === 'owner' || busy === `member-${member.id}`} onchange={(event) => changeRole(member, event.currentTarget.value)}><option value="viewer">Viewer</option><option value="artisan">Artisan</option><option value="accountant">Accountant</option><option value="studio_manager">Studio manager</option>{#if member.role === 'owner'}<option value="owner">Owner</option>{/if}</select></label>
				<div class="actions">
					{#if canTransfer && member.id !== session.me?.id && member.role !== 'owner'}<button class="secondary" disabled={busy === `member-${member.id}`} onclick={() => transfer(member.id)}>Transfer ownership</button>{/if}
					{#if canManage && member.id !== session.me?.id && member.role !== 'owner'}<button class="danger" disabled={busy === `member-${member.id}`} onclick={() => remove(member)}>Remove</button>{/if}
				</div>
				{#if member.operation_id && (isPending(member.operation_state) || member.operation_state === 'dead_letter')}<div class="member-operation"><OperationCard id={member.operation_id} compact onsettled={load} /></div>{/if}
			</article>
		{/each}
	</div>
</section>

{#if canManage}
	<section class="section invite-grid" aria-labelledby="invite-title">
		<form class="card form" onsubmit={(event) => { event.preventDefault(); void sendInvite(); }}>
			<div><h2 id="invite-title">Invite someone</h2><p class="muted">Owner access is transferred separately and can’t be granted by invitation.</p></div>
			<label>Email<input type="email" bind:value={invite.email} autocomplete="email" required /></label>
			<label>Role<select bind:value={invite.role}><option value="viewer">Viewer</option><option value="artisan">Artisan</option><option value="accountant">Accountant</option><option value="studio_manager">Studio manager</option></select></label>
			<label>Invitation language<select bind:value={invite.locale}><option value="en">English</option><option value="fr">Français</option></select></label>
			<div class="form-actions"><button disabled={busy === 'invite'}>{busy === 'invite' ? 'Sending…' : 'Send invitation'}</button></div>
		</form>
		<div class="stack pending-invites"><div><h2>Pending invitations</h2><p class="muted">Resending invalidates the previous single-use link.</p></div>
			{#if invitations.length === 0}<div class="card empty">No pending invitations.</div>{/if}
			{#each invitations as pending (pending.id)}<article class="card row"><div><strong>{pending.email}</strong><div class="muted">{roleLabel(pending.role)} · {pending.locale.toUpperCase()} · expires {formatInstant(pending.expires_at)}</div><div class="muted">Sent {pending.sent_count} time{pending.sent_count === 1 ? '' : 's'}, last {formatInstant(pending.last_sent_at)}</div></div><div class="actions"><button class="secondary" disabled={busy === `invite-${pending.id}`} onclick={() => resend(pending.id)}>Resend</button><button class="danger" disabled={busy === `invite-${pending.id}`} onclick={() => revoke(pending.id)}>Revoke</button></div></article>{/each}
		</div>
	</section>
{/if}

<section class="section" aria-labelledby="services-title">
	<div class="section-header"><div><h2 id="services-title">Connected services</h2><p class="muted">Links become available only after the current access configuration is fully applied.</p></div></div>
	<div class="grid services">
		{#if integrations.length === 0}<div class="card empty">Services are still being provisioned.</div>{/if}
		{#each integrations as integration (integration.service)}
			<article class="card stack"><div class="row"><strong>{sentence(integration.service)}</strong><StatusBadge state={integration.health} /></div><p class="muted">Access version {integration.applied_epoch} of {integration.desired_epoch}{integration.error ? ` · ${sentence(integration.error)}` : ''}</p>{#if integrationReady(integration) && integration.external_url}<a class="button" href={integration.external_url} target="_blank" rel="noreferrer">Open {sentence(integration.service)} ↗</a>{:else}<button disabled>Available after reconciliation</button>{/if}</article>
		{/each}
	</div>
</section>

<style>
	.transfer{margin-bottom:1rem;border-color:#d8c897;background:#fffdf5}.reconciliation{font-size:.78rem;margin-top:.3rem}.member-operation{grid-column:1/-1}.invite-grid{display:grid;grid-template-columns:minmax(260px,.7fr) minmax(360px,1.3fr);gap:1rem;align-items:start}.pending-invites{min-width:0}.services{grid-template-columns:repeat(auto-fit,minmax(240px,1fr))}@media(max-width:850px){.invite-grid{grid-template-columns:1fr}}
</style>
