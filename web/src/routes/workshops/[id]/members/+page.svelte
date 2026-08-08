<script lang="ts">
	import { page } from '$app/state';
	import { request, session } from '$lib/session.svelte';
	const id = $derived(page.params.id ?? '');
	let workshop = $state<any>();
	let members = $state<any[]>([]);
	let integrations = $state<any[]>([]);
	let invitations = $state<any[]>([]);
	let transfers = $state<any[]>([]);
	let error = $state('');
	let invite = $state({ email: '', role: 'artisan', locale: 'en' });
	$effect(() => { id; void load(); });
	const key = () => crypto.randomUUID();
	async function load() {
		try {
			[workshop, members, integrations] = await Promise.all([
				request<any>(`/v1/workshops/${id}`),
				request<any[]>(`/v1/workshops/${id}/members`),
				request<any[]>(`/v1/workshops/${id}/integrations`)
			]);
			if (['owner', 'studio_manager'].includes(workshop.role)) {
				invitations = await request<any[]>(`/v1/workshops/${id}/invitations`);
			}
			transfers = await request<any[]>(`/v1/workshops/${id}/ownership-transfers`);
		} catch (e) { error = String(e); }
	}
	async function sendInvite() { try { await request(`/v1/workshops/${id}/invitations`, { method:'POST', headers:{'idempotency-key':key()}, body:JSON.stringify(invite) }); invite.email=''; await load(); } catch(e){ error=String(e); } }
	async function resend(invitationId:string) { try { await request(`/v1/invitations/${invitationId}/resend`, {method:'POST',headers:{'idempotency-key':key()}}); await load(); } catch(e){error=String(e);} }
	async function revoke(invitationId:string) { if(!confirm('Revoke this invitation?'))return; try { await request(`/v1/invitations/${invitationId}`,{method:'DELETE'});await load(); }catch(e){error=String(e);} }
	async function role(user:string,value:string) { try { await request(`/v1/workshops/${id}/members/${user}`, {method:'PATCH',headers:{'idempotency-key':key()},body:JSON.stringify({role:value})});await load(); }catch(e){error=String(e);} }
	async function remove(user:string) { if(!confirm('Remove this person from the workshop?'))return;try{await request(`/v1/workshops/${id}/members/${user}`,{method:'DELETE',headers:{'idempotency-key':key()}});await load();}catch(e){error=String(e);} }
	async function transfer(user:string) { if(!confirm('Ask this person to become the owner?'))return;try{await request(`/v1/workshops/${id}/ownership-transfers`,{method:'POST',headers:{'idempotency-key':key()},body:JSON.stringify({to_user_id:user})});await load();}catch(e){error=String(e);} }
	async function acceptTransfer(transferId:string) { try{await request(`/v1/ownership-transfers/${transferId}/accept`,{method:'POST',headers:{'idempotency-key':key()}});await load();}catch(e){error=String(e);} }
</script>

<svelte:head><title>{workshop?.display_name || 'Members'} · MakersBrain</title></svelte:head>
<p><a href="/">← Workshops</a></p>
{#if workshop}<div class="row"><div><h1>{workshop.display_name}</h1><p class="muted">You are {workshop.role}</p></div><div class="actions"><a class="button secondary" href={`/workshops/${id}/database`}>Database & backups</a><span class="status">{workshop.status}</span></div></div>{/if}
{#if error}<p class="error">{error}</p>{/if}

{#each transfers as transfer}
	{#if transfer.can_accept}<aside class="card row"><div><strong>Ownership transfer</strong><div class="muted">The current owner asked you to take ownership.</div></div><button onclick={() => acceptTransfer(transfer.id)}>Accept ownership</button></aside>{/if}
{/each}

<section class="stack"><h2>Members</h2>
{#each members as member}
	<article class="card member"><div><strong>{member.display_name || member.email}</strong><div class="muted">{member.email}</div><div class="actions">{#each Object.entries(member.targets || {}) as [target,value]}<span class:degraded={(value as any).state==='degraded'} class="target">{target}: {(value as any).state}</span>{/each}</div></div>
	<select value={member.role} disabled={member.role==='owner'} onchange={(e)=>role(member.id,e.currentTarget.value)}><option value="viewer">Viewer</option><option value="artisan">Artisan</option><option value="accountant">Accountant</option><option value="studio_manager">Studio manager</option><option value="owner">Owner</option></select>
	<div class="actions">{#if member.id!==session.me?.id && member.role!=='owner'}<button class="secondary" onclick={()=>transfer(member.id)}>Transfer ownership</button><button class="danger" onclick={()=>remove(member.id)}>Remove</button>{/if}</div></article>
{/each}</section>

{#if workshop && ['owner','studio_manager'].includes(workshop.role)}
<section class="card" style="margin-top:1rem"><h2>Invite someone</h2><form class="form" onsubmit={(e)=>{e.preventDefault();void sendInvite()}}><label>Email<input type="email" bind:value={invite.email} required/></label><label>Role<select bind:value={invite.role}><option value="viewer">Viewer</option><option value="artisan">Artisan</option><option value="accountant">Accountant</option><option value="studio_manager">Studio manager</option></select></label><button>Send invitation</button></form></section>
<section class="stack" style="margin-top:1rem"><h2>Pending invitations</h2>{#each invitations as pending}<article class="card row"><div><strong>{pending.email}</strong><div class="muted">{pending.role} · sent {pending.sent_count} time(s)</div></div><div class="actions"><button class="secondary" onclick={()=>resend(pending.id)}>Resend</button><button class="danger" onclick={()=>revoke(pending.id)}>Revoke</button></div></article>{/each}</section>
{/if}

<section class="stack" style="margin-top:1rem"><h2>Connected services</h2>{#each integrations as integration}<article class="card row"><div><strong>{integration.service}</strong><div><a href={integration.url}>{integration.url}</a></div></div><span class="status">{integration.health}</span></article>{/each}</section>
