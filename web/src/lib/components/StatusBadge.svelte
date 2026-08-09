<script lang="ts">
	import { stateLabel, tone as stateTone } from '$lib/format';
	let { state, label }: { state?: string; label?: string } = $props();
</script>

<span class="badge {stateTone(state)}"><span class="dot" aria-hidden="true"></span>{label ?? stateLabel(state ?? '')}</span>
