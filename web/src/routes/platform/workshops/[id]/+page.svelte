<script lang="ts">
	import { page } from '$app/state';
	import OperatorGuard from '$lib/components/OperatorGuard.svelte';
	import OperationCard from '$lib/components/OperationCard.svelte';
	import PlatformNav from '$lib/components/PlatformNav.svelte';
	import StatusBadge from '$lib/components/StatusBadge.svelte';
	import { formatInstant, roleLabel, sentence } from '$lib/format';
	import { request } from '$lib/session.svelte';
	const id = $derived(page.params.id ?? '');
	let workshop = $state<any>(); let error = $state(''); let loading = $state(true);
	let reconciling = $state(false); let operationId = $state(''); let notice = $state('');
	$effect(() => { id; void load(); const timer = window.setInterval(() => void load(false), 8000); return () => window.clearInterval(timer); });
	async function load(showError = true) { try { workshop = await request(`/v1/platform/workshops/${id}`); if (showError) error = ''; } catch (cause) { if (showError) error = cause instanceof Error ? cause.message : String(cause); } finally { loading = false; } }
	async function reconcile() { reconciling = true; error = ''; notice = ''; try { const result = await request<{operation_id:string}>(`/v1/platform/workshops/${id}/reconcile`, { method:'POST', headers:{'idempotency-key':crypto.randomUUID()} }); operationId = result.operation_id; notice = 'A complete tenant observation and repair pass was queued.'; await load(); } catch (cause) { error = cause instanceof Error ? cause.message : String(cause); } finally { reconciling = false; } }
</script>

<svelte:head><title>{workshop?.display_name ?? 'Workshop'} · Platform · MakersBrain</title></svelte:head>
<OperatorGuard>
	<p><a href="/platform/workshops">← Workshop fleet</a></p>
	<header class="page-header"><div><p class="eyebrow">Platform workshop</p><h1>{workshop?.display_name ?? 'Workshop'}</h1><p class="muted">{workshop?.slug}</p></div>{#if workshop}<div class="actions"><StatusBadge state={workshop.status} /><span class="badge">{workshop.plan}</span><button disabled={reconciling} onclick={reconcile}>{reconciling ? 'Queuing…' : 'Observe & repair'}</button></div>{/if}</header>
	<PlatformNav />
	{#if error}<p class="error">{error}</p>{/if}
	{#if notice}<p class="notice">{notice}</p>{/if}
	{#if operationId}<OperationCard id={operationId} onsettled={load} />{/if}
	{#if loading}<div class="card empty">Loading workshop…</div>{:else if workshop}
		<section class="card facts"><div><span class="muted">Legal name</span><strong>{workshop.legal_name ?? '—'}</strong></div><div><span class="muted">Country</span><strong>{workshop.country_code ?? '—'}</strong></div><div><span class="muted">Primary domain</span><strong>{workshop.primary_hostname ?? 'Not published'}</strong></div><div><span class="muted">Created</span><strong>{formatInstant(workshop.created_at)}</strong></div></section>
		<section class="section"><div class="section-header"><div><h2>Plan & entitlement</h2><p class="muted">Signed effective limits and current-month metering; the signature itself is not exposed.</p></div></div>{#if workshop.entitlement}<div class="card facts"><div><span class="muted">Plan</span><strong>{workshop.entitlement.plan}</strong></div><div><span class="muted">State</span><StatusBadge state={workshop.entitlement.status} /></div><div><span class="muted">Version</span><strong>{workshop.entitlement.version}</strong></div><div><span class="muted">Expires</span><strong>{formatInstant(workshop.entitlement.expires_at)}</strong></div>{#each workshop.usage as counter}<div><span class="muted">{sentence(counter.metric)}</span><strong>{counter.quantity}</strong></div>{/each}</div>{:else}<div class="card empty">No signed entitlement has been issued yet.</div>{/if}</section>
		<section class="section"><div class="section-header"><div><h2>Services</h2><p class="muted">Logical instances and applied configuration epochs; credentials are never returned.</p></div></div><div class="grid services">{#if workshop.services.length === 0}<div class="card empty">No service instances yet.</div>{/if}{#each workshop.services as service}<article class="card stack"><div class="row"><strong>{sentence(service.service)}</strong><StatusBadge state={service.health} /></div><p class="muted">Release {service.release_id ?? 'not reported'} · epoch {service.applied_epoch}/{service.desired_epoch}</p>{#if service.error}<p class="error">{sentence(service.error)}</p>{/if}<a href={service.url} target="_blank" rel="noreferrer">Open service ↗</a></article>{/each}</div></section>
		<section class="section"><div class="section-header"><h2>Members</h2><span class="muted">Read-only operator view</span></div><div class="card table-wrap"><table><thead><tr><th>Person</th><th>Role</th><th>State</th></tr></thead><tbody>{#each workshop.members as member}<tr><td><strong>{member.display_name ?? member.email}</strong><div class="muted">{member.email}</div></td><td>{roleLabel(member.role)}</td><td><StatusBadge state={member.status} /></td></tr>{/each}</tbody></table></div></section>
		<section class="section"><div class="section-header"><div><h2>Recent operations</h2><p class="muted">Newest durable work for this workshop.</p></div><a href={`/platform/operations?workshop_id=${id}`}>Open operations →</a></div><div class="card table-wrap">{#if workshop.operations.length === 0}<div class="empty">No operations.</div>{:else}<table><thead><tr><th>Operation</th><th>State</th><th>Attempts</th><th>Started</th></tr></thead><tbody>{#each workshop.operations as operation}<tr><td><a href={`/operations/${operation.id}`}><strong>{sentence(operation.kind)}</strong></a>{#if operation.failure_class}<div class="muted">{sentence(operation.failure_class)}</div>{/if}</td><td><StatusBadge state={operation.state} /></td><td>{operation.attempt}/{operation.max_attempts}</td><td>{formatInstant(operation.created_at)}</td></tr>{/each}</tbody></table>{/if}</div></section>
	{/if}
</OperatorGuard>

<style>.services{grid-template-columns:repeat(auto-fit,minmax(240px,1fr))}</style>
