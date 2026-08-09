<script lang="ts">
	import { page } from '$app/state';
	import { API } from '$lib/config';
	import { roleLabel } from '$lib/format';
	import { bearer, request } from '$lib/session.svelte';
	import { signIn } from '$lib/oidc';
	const token = $derived(page.params.token ?? '');
	let invitation = $state<{ email: string; role: string; locale: string; workshop_name: string }>();
	let error = $state('');
	let accepting = $state(false);
	let accepted = $state<{ workshop_id: string; user_id: string; operation_id: string }>();
	$effect(() => { token; void load(); });
	async function load() {
		error = '';
		try {
			const response = await fetch(`${API}/v1/invitations/${encodeURIComponent(token)}/validate`);
			if (!response.ok) throw new Error('This invitation is invalid, expired, or already used.');
			invitation = await response.json();
		} catch (cause) { error = cause instanceof Error ? cause.message : String(cause); }
	}
	async function accept() {
		if (!await bearer()) { await signIn(page.url.pathname); return; }
		accepting = true; error = '';
		try { accepted = await request(`/v1/invitations/${encodeURIComponent(token)}/accept`, { method: 'POST' }); }
		catch (cause) { error = cause instanceof Error ? cause.message : String(cause); }
		finally { accepting = false; }
	}
</script>

<svelte:head><title>{invitation ? `Join ${invitation.workshop_name}` : 'Workshop invitation'} · MakersBrain</title></svelte:head>
<main class="invitation-shell"><div class="card invitation-card"><a class="brand" href="/"><span class="brand-mark" aria-hidden="true">M</span><span>MakersBrain</span></a><hr class="divider" />
	{#if accepted}<p class="eyebrow">Invitation accepted</p><h1>Welcome to the workshop</h1><p>Your access is being prepared across the connected services. You can follow its progress from the workshop.</p><a class="button" href={`/workshops/${accepted.workshop_id}/members`}>Open workshop</a>
	{:else if invitation}<p class="eyebrow">Workshop invitation</p><h1>Join {invitation.workshop_name}</h1><p>You were invited as <strong>{roleLabel(invitation.role)}</strong> using <strong>{invitation.email}</strong>.</p><p class="muted">Sign in with this verified email. MakersBrain will not expose application groups or create another password.</p>{#if error}<p class="error">{error}</p>{/if}<button disabled={accepting} onclick={accept}>{accepting ? 'Accepting…' : 'Sign in and accept'}</button>
	{:else if error}<h1>Invitation unavailable</h1><p class="error">{error}</p><a class="button secondary" href="/">Return to MakersBrain</a>
	{:else}<span class="spinner" aria-hidden="true"></span><p>Checking invitation…</p>{/if}
</div></main>

<style>.invitation-shell{min-height:100vh;display:grid;place-items:center;padding:1rem}.invitation-card{width:min(100%,34rem);padding:1.5rem}.invitation-card h1{font-size:2.2rem}</style>
