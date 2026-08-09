<script lang="ts">
	import '../app.css';
	import { page } from '$app/state';
	import { ACCOUNT_URL } from '$lib/config';
	import { currentIdToken, discard, establish, session } from '$lib/session.svelte';
	import { logoutUrl, signIn } from '$lib/oidc';
	let { children } = $props();
	const publicRoute = $derived(page.url.pathname.startsWith('/oauth/') || page.url.pathname === '/signed-out' || page.url.pathname.startsWith('/invitations/'));
	let started = false;
	$effect(() => {
		if (!publicRoute && !started) {
			started = true;
			void establish(page.url.pathname + page.url.search);
		}
	});
	function leave() {
		const url = logoutUrl(currentIdToken());
		discard();
		location.assign(url);
	}
</script>

{#if publicRoute}
	{@render children()}
{:else if session.lost}
	<main class="auth-state card">
		<h1>Your session needs to be renewed</h1>
		<p class="muted">Sign in again to continue. If access is refused, this page will stop here instead of repeatedly redirecting you.</p>
		<button onclick={() => signIn(page.url.pathname + page.url.search)}>Sign in again</button>
	</main>
{:else if session.ready && session.me}
	<div class="app-shell">
		<header class="topbar">
			<div class="topbar-inner">
				<a class="brand" href="/" aria-label="MakersBrain home"><span class="brand-mark" aria-hidden="true">M</span><span>MakersBrain</span></a>
				<nav class="global-nav" aria-label="Main navigation"><a href="/" class:active={page.url.pathname === '/'}>Workshops</a>{#if session.me.is_operator}<a href="/platform" class:active={page.url.pathname.startsWith('/platform')}>Platform</a>{/if}</nav>
				<div class="account-menu">
					<a class="account-link" href={ACCOUNT_URL} target="_blank" rel="noreferrer">Account & security</a>
					<span class="account-email">{session.me.email}</span>
					<button class="quiet" onclick={leave}>Sign out</button>
				</div>
			</div>
		</header>
		<main class="shell">{@render children()}</main>
	</div>
{:else if session.ready}
	<main class="auth-state card">
		<h1>We couldn’t open your account</h1>
		<p class="error">{session.error || 'This verified account is not linked to MakersBrain.'}</p>
		<button onclick={() => signIn(page.url.pathname)}>Try another account</button>
	</main>
{:else}
	<main class="auth-state"><span class="spinner" aria-hidden="true"></span><p>Opening your workshops…</p></main>
{/if}
