<script lang="ts">
	import OperatorGuard from '$lib/components/OperatorGuard.svelte';
	import PlatformNav from '$lib/components/PlatformNav.svelte';
	import StatusBadge from '$lib/components/StatusBadge.svelte';
	import { formatInstant } from '$lib/format';
	import { request } from '$lib/session.svelte';
	import type { PlatformWorkshopResponse } from '$lib/generated/control-api';
	let workshops = $state<PlatformWorkshopResponse[]>([]); let query = $state(''); let status = $state(''); let error = $state(''); let loading = $state(true);
	const filtered = $derived(workshops.filter((item) => (!status || item.status === status) && (!query.trim() || `${item.display_name} ${item.slug}`.toLowerCase().includes(query.trim().toLowerCase()))));
	$effect(() => { void load(); });
	async function load() { try { workshops = await request<PlatformWorkshopResponse[]>('/v1/platform/workshops'); error = ''; } catch (cause) { error = cause instanceof Error ? cause.message : String(cause); } finally { loading = false; } }
</script>

<svelte:head><title>Platform workshops · MakersBrain</title></svelte:head>
<OperatorGuard>
	<header class="page-header"><div><p class="eyebrow">Platform administration</p><h1>Workshop fleet</h1><p class="muted">All tenant boundaries and their current lifecycle state.</p></div><button class="secondary" onclick={load}>Refresh</button></header>
	<PlatformNav />
	{#if error}<p class="error">{error}</p>{/if}
	<div class="card filters"><label>Search<input type="search" bind:value={query} placeholder="Name or slug" /></label><label>Status<select bind:value={status}><option value="">All statuses</option><option value="provisioning">Provisioning</option><option value="trial">Trial</option><option value="active">Active</option><option value="past_due">Past due</option><option value="restricted">Restricted</option><option value="suspended">Suspended</option></select></label></div>
	<section class="section card table-wrap">{#if loading}<div class="empty">Loading workshops…</div>{:else if filtered.length === 0}<div class="empty">No workshops match.</div>{:else}<table><thead><tr><th>Workshop</th><th>Status</th><th>Plan</th><th>Members</th><th>Services</th><th>Created</th></tr></thead><tbody>{#each filtered as item (item.id)}<tr><td><a href={`/platform/workshops/${item.id}`}><strong>{item.display_name}</strong><div class="muted">{item.slug}</div></a></td><td><StatusBadge state={item.status} /></td><td>{item.plan}</td><td>{item.member_count}</td><td>{#if item.degraded_service_count}<span class="badge bad">{item.degraded_service_count} degraded</span>{:else}<span class="muted">No alerts</span>{/if}</td><td>{formatInstant(item.created_at)}</td></tr>{/each}</tbody></table>{/if}</section>
</OperatorGuard>

<style>.filters{display:grid;grid-template-columns:2fr 1fr;gap:1rem}@media(max-width:600px){.filters{grid-template-columns:1fr}}</style>
