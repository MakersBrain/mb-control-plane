<script lang="ts">
	import OperatorGuard from '$lib/components/OperatorGuard.svelte';
	import PlatformNav from '$lib/components/PlatformNav.svelte';
	import StatusBadge from '$lib/components/StatusBadge.svelte';
	import { formatInstant, sentence } from '$lib/format';
	import { request } from '$lib/session.svelte';
	import type { AuditEventResponse } from '$lib/generated/control-api';
	let events = $state<AuditEventResponse[]>([]); let query = $state(''); let error = $state(''); let loading = $state(true);
	const filtered = $derived(events.filter((item) => !query.trim() || JSON.stringify(item).toLowerCase().includes(query.trim().toLowerCase())));
	$effect(() => { void load(); });
	async function load() { try { events = await request<AuditEventResponse[]>('/v1/platform/audit-events?limit=200'); error = ''; } catch (cause) { error = cause instanceof Error ? cause.message : String(cause); } finally { loading = false; } }
	const detail = (value: Record<string, unknown>) => Object.entries(value || {}).map(([key, item]) => `${sentence(key)}: ${String(item)}`).join(' · ');
</script>

<svelte:head><title>Audit journal · MakersBrain</title></svelte:head>
<OperatorGuard>
	<header class="page-header"><div><p class="eyebrow">Platform administration</p><h1>Audit journal</h1><p class="muted">Append-only answers to who requested what, under which workshop authority, and with what result.</p></div><button class="secondary" onclick={load}>Refresh</button></header>
	<PlatformNav />
	{#if error}<p class="error">{error}</p>{/if}
	<label class="card search">Filter loaded events<input type="search" bind:value={query} placeholder="Actor, action, workshop, target…" /></label>
	<section class="section card table-wrap">{#if loading}<div class="empty">Loading audit journal…</div>{:else if filtered.length === 0}<div class="empty">No events match.</div>{:else}<table><thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Workshop</th><th>Outcome</th><th>Target and detail</th></tr></thead><tbody>{#each filtered as item (item.id)}<tr><td>{formatInstant(item.created_at)}</td><td>{item.actor_email ?? 'System'}</td><td><strong>{sentence(item.action)}</strong><div class="muted ident">{item.correlation_id}</div></td><td>{item.workshop_name ?? 'Platform'}</td><td><StatusBadge state={item.outcome} /></td><td>{item.target_type ? `${sentence(item.target_type)} ${item.target_id ?? ''}` : '—'}{#if Object.keys(item.detail || {}).length}<div class="muted">{detail(item.detail)}</div>{/if}</td></tr>{/each}</tbody></table>{/if}</section>
</OperatorGuard>

<style>.search{max-width:36rem}.ident{font-family:ui-monospace,monospace;font-size:.7rem}</style>
