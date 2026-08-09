<script lang="ts">
	import { page } from '$app/state';
	import OperationCard from '$lib/components/OperationCard.svelte';
	const id = $derived(page.params.id ?? '');
</script>

<svelte:head><title>Operation · MakersBrain</title></svelte:head>
<p><a href="/">← Workshops</a></p>
<header class="page-header"><div><p class="eyebrow">Durable operation</p><h1>Operation details</h1><p class="muted">Safe progress and retry information. Provider payloads and secrets are never shown.</p></div></header>
{#if id}<OperationCard {id} />{/if}
