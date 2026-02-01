# opForge --- Sections and Relocation (Draft Notes)


## Related documents

- **Core spec** (directives + `.section` family): [opforge_core_spec_v0_3a.md](opforge_core_spec_v0_3a.md)
- **Family/CPU/Dialect packs + `encode`** (emits bytes into sections): [opforge_family_cpu_dialect_and_encoding_v0_2a.md](opforge_family_cpu_dialect_and_encoding_v0_2a.md)

---
*Draft v0.2*

This document sketches how **sections** provide grouping, positioning,
relocation, and linking in opForge, inspired by 64tass semantics.

------------------------------------------------------------------------

## Core Principle

`.section` defines **where bytes belong logically**. Relocation and
linking arise from moving sections in memory.

------------------------------------------------------------------------

## Section Declaration vs Selection

-   `.dsection <name>` declares a section and its constraints
-   `.section <name>` selects it as the current output target
-   `.endsection` restores the previous section

`.dsection` does not emit bytes.

------------------------------------------------------------------------

## Hierarchical Sections

Sections may be nested to form a hierarchy:

-   `bank1.code`
-   `bank1.data`
-   `zp`
-   `rom.text`

Hierarchy allows: - reuse of source across banks - late binding of
physical placement

------------------------------------------------------------------------

## DSection Attributes

A declared section may specify:

-   `org` --- fixed start address
-   `align` --- alignment constraint
-   `region` --- named memory region
-   `addrspace` --- CPU, RAM, VRAM, MMIO
-   flags --- read/write/exec

------------------------------------------------------------------------

## Emission and Relocation

All emitted bytes belong to the current section.

When an emitted value references a symbol whose address is not yet
known: - placeholder bytes are emitted - a relocation record is added to
the section

Relocations belong to sections.

------------------------------------------------------------------------

## Linking Model

Linking consists of:

1.  Placing sections according to constraints
2.  Computing final symbol addresses
3.  Applying relocation records

No implicit linking occurs without sections.

------------------------------------------------------------------------

## Relationship to Encoding

Encoding statements (`encode`) emit bytes into sections. Relocations are
created automatically when needed.

Encoding remains CPU-agnostic; placement is section-driven.

------------------------------------------------------------------------

------------------------------------------------------------------------

## `.dsection` and `.section` (64tass-inspired)

- `.dsection <name>` declares a section and its constraints (grouping + positioning intent).
- `.section <name>` selects the current output sink (bytes emitted now belong to that section).
- `.endsection` restores the previous section.

Declaring a section does not emit bytes; it only defines metadata used during placement/linking.

------------------------------------------------------------------------

## Relocation creation

Relocations can be created:

- **implicitly** by emission directives (e.g. `.word target`) when `target` is not yet absolute-resolved
- **explicitly** via a relocation directive (e.g. `.reloc abs16, target, addend`) when the encoder wants full control

In both cases, relocation records belong to the current section at the current output offset.

## Summary

-   `.section` is the relocation domain
-   `.dsection` defines layout intent
-   Linking is section placement + patching
-   This scales from flat binaries to banked systems

This model supports both tiny systems and full linkers.