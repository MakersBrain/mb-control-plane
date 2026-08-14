<script lang="ts">
	import OperatorGuard from '$lib/components/OperatorGuard.svelte';
	import PlatformNav from '$lib/components/PlatformNav.svelte';
	import StatusBadge from '$lib/components/StatusBadge.svelte';
	import { formatInstant } from '$lib/format';
	import { request } from '$lib/session.svelte';
	import type { ApplicationReleaseResponse } from '$lib/generated/control-api';
	let releases = $state<ApplicationReleaseResponse[]>([]), error = $state(''), loading = $state(true);
	$effect(() => { void load(); });
	async function load() { try { releases = await request<ApplicationReleaseResponse[]>('/v1/platform/releases'); error = ''; } catch (cause) { error = cause instanceof Error ? cause.message : String(cause); } finally { loading = false; } }
</script>

<svelte:head><title>Application releases · MakersBrain</title></svelte:head>
<OperatorGuard>
	<header class="page-header"><div><p class="eyebrow">Platform administration</p><h1>Application releases</h1><p class="muted">Immutable Odoo artifacts and their fleet-adoption state.</p></div><button class="secondary" onclick={load}>Refresh</button></header>
	<PlatformNav />
	{#if error}<p class="error" role="alert">{error}</p>{/if}
	{#if loading}<div class="card empty">Loading releases…</div>{:else}<div class="card table-wrap">{#if releases.length === 0}<div class="empty">No verified release manifests have been published.</div>{:else}<table><thead><tr><th>Release</th><th>State</th><th>Class</th><th>Odoo</th><th>Published</th></tr></thead><tbody>{#each releases as release (release.id)}<tr><td><a href={`/platform/releases/${release.id}`}><strong>{release.id}</strong></a><div class="muted digest">{release.image_digest}</div></td><td><StatusBadge state={release.status} /></td><td>{release.change_class}</td><td>{release.odoo_version}</td><td>{formatInstant(release.published_at)}</td></tr>{/each}</tbody></table>{/if}</div>{/if}
</OperatorGuard>

<style>.digest{font-family:monospace;font-size:.72rem;max-width:32rem;overflow:hidden;text-overflow:ellipsis}</style>
