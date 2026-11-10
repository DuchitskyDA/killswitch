<script lang="ts">
  import type { Tunnel } from "../lib/api";

  // Строка туннеля: имя адаптера и поднят он или опущен.
  let { tunnels }: { tunnels: Tunnel[] } = $props();
</script>

{#if tunnels.length === 0}
  <p class="tunnel muted">Адаптер туннеля не найден</p>
{:else}
  <ul class="tunnel">
    {#each tunnels as t}
      <li>
        <span class="muted">Туннель</span>
        <span class="mono">{t.name}</span>
        {#if t.up}поднят{:else}<b>опущен</b>{/if}
      </li>
    {/each}
  </ul>
{/if}

<style>
  .tunnel {
    display: grid;
    gap: 2px;
    justify-items: center;
    text-align: center;
  }

  b {
    font-weight: 650;
  }
</style>
