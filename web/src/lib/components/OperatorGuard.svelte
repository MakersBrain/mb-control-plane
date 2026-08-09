<script lang="ts">
	import { session } from '$lib/session.svelte';
	let { children } = $props();
</script>

{#if session.me?.is_operator}{@render children()}{:else}<div class="card empty"><h1>Operator access required</h1><p>This area is restricted to explicitly configured platform operators.</p><a class="button secondary" href="/">Return to workshops</a></div>{/if}
