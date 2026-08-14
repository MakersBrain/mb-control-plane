<script lang="ts">
	import { onMount } from 'svelte';
	import { API } from '$lib/config';
	import { roleLabel } from '$lib/format';
	import { bearer, request } from '$lib/session.svelte';
	import { signIn } from '$lib/oidc';

	let token = $state('');
	let invitation = $state<{ email: string; role: string; locale: string; workshop_name: string }>();
	let error = $state('');
	let accepting = $state(false);
	let commandKey = $state('');
	let accepted = $state<{ workshop_id: string; user_id: string; operation_id: string }>();

	onMount(() => {
		commandKey = crypto.randomUUID();
		const fragment = new URLSearchParams(location.hash.slice(1));
		token = fragment.get('token') ?? '';
		history.replaceState(null, '', location.pathname);
		void load();
	});

	async function load() {
		error = '';
		if (!token) {
			error = 'This invitation link is incomplete.';
			return;
		}
		try {
			const response = await fetch(`${API}/v1/invitations/validate`, {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({ token }),
				cache: 'no-store',
				referrerPolicy: 'no-referrer'
			});
			if (!response.ok) throw new Error('This invitation is invalid, expired, or already used.');
			invitation = await response.json();
		} catch (cause) {
			error = cause instanceof Error ? cause.message : String(cause);
		}
	}

	async function accept() {
		if (!await bearer()) {
			const fragment = new URLSearchParams({ token });
			await signIn(`/invitations/accept#${fragment}`);
			return;
		}
		accepting = true;
		error = '';
		try {
			accepted = await request('/v1/invitations/accept', {
				method: 'POST',
				headers: { 'idempotency-key': commandKey },
				body: JSON.stringify({ token })
			});
			token = '';
		} catch (cause) {
			error = cause instanceof Error ? cause.message : String(cause);
		} finally {
			accepting = false;
		}
	}
</script>

<svelte:head>
	<title>{invitation ? `Join ${invitation.workshop_name}` : 'Workshop invitation'} · MakersBrain</title>
	<meta name="referrer" content="no-referrer" />
</svelte:head>

<main class="invitation-shell"><div class="card invitation-card"><a class="brand" href="/"><span class="brand-mark" aria-hidden="true">M</span><span>MakersBrain</span></a><hr class="divider" />
	{#if accepted}<p class="eyebrow">Invitation accepted</p><h1>Welcome to the workshop</h1><p>Your access is being prepared across the connected services. You can follow its progress from the workshop.</p><a class="button" href={`/workshops/${accepted.workshop_id}/members`}>Open workshop</a>
	{:else if invitation}<p class="eyebrow">Workshop invitation</p><h1>Join {invitation.workshop_name}</h1><p>You were invited as <strong>{roleLabel(invitation.role)}</strong> using <strong>{invitation.email}</strong>.</p><p class="muted">Sign in with this verified email. MakersBrain will not expose application groups or create another password.</p>{#if error}<p class="error">{error}</p>{/if}<button disabled={accepting} onclick={accept}>{accepting ? 'Accepting…' : 'Sign in and accept'}</button>
	{:else if error}<h1>Invitation unavailable</h1><p class="error">{error}</p><a class="button secondary" href="/">Return to MakersBrain</a>
	{:else}<span class="spinner" aria-hidden="true"></span><p>Checking invitation…</p>{/if}
</div></main>

<style>.invitation-shell{min-height:100vh;display:grid;place-items:center;padding:1rem}.invitation-card{width:min(100%,34rem);padding:1.5rem}.invitation-card h1{font-size:2.2rem}</style>
