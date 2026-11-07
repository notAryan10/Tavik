# tavik-cgroups

`tavik-cgroups` provides the cgroups v2 resource governance engine for TAVIK container workloads.

## Supported Controllers & Interfaces

- **CPU Governance**: `cpu.max` (quota and period enforcement), `cpu.weight` (relative share distribution).
- **Memory Governance**: `memory.max` (hard byte limit), `memory.swap.max` (swap space boundary), `memory.high` (throttled allocation watermark).
- **Process Governance**: `pids.max` (process/thread concurrency limit to prevent fork bombs).
- **Lifecycle & Termination**: `cgroup.kill` (atomic kill signal for all cgroup members), atomic process enrollment via `cgroup.procs`.
