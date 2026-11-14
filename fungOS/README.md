# fungOS

Bootable Debian-based nodes with Mycelium enrollment and signed software delivery.
The optional edge profile adds Unibus and the native Canvas Wayland compositor.

![fungOS edge running Canvas with two Wayland terminals in QEMU](https://raw.githubusercontent.com/mycelium-linux/fungos-web/main/dist/assets/fungos-workspace.png)

Actual QEMU framebuffer capture, 6 October 2026—not a mockup. The desktop uses
the original procedural Undergrowth background; the applications are Weston
Wayland terminals. These are development builds, not a stable distribution release.

## Source layout

- The public [distribution repository](https://github.com/mycelium-linux/fungos) owns
  the generic base builder and profile declarations. This directory still holds
  integration and qualification work awaiting migration:
  [base](base/README.md), [edge](edge/README.md), and [packages](packages/README.md).
- [mycelium-linux/fungos-web](https://github.com/mycelium-linux/fungos-web) owns the public
  website, documentation pages and screenshot assets. See [fungos.dev](https://fungos.dev).
- Mycelium, Unibus, Canvas and the compute components remain separately owned
  projects—not copies of their implementations inside an OS repository.

The public distribution repository is [mycelium-linux/fungos](https://github.com/mycelium-linux/fungos),
licensed `MIT OR Apache-2.0`. Its first import contains the generic base builder,
profile declarations and real desktop captures; other integration work remains here.
`fungos-web` is the website, not the OS build repository.

## Desktop

![fungOS edge desktop with the Undergrowth background](https://raw.githubusercontent.com/mycelium-linux/fungos-web/main/dist/assets/fungos-desktop.png)

The public website repository retains the [capture provenance and asset notices](https://github.com/mycelium-linux/fungos-web/blob/main/ASSET-NOTICES.md).

## Development notes

First-party Debian package delivery is being qualified separately from native
binary updates. See [signed APT qualification](packages/README.md) for verified
install/upgrade/recovery and persistent QEMU reboot evidence.

`fungOS` is the working strategy map for the open FPL computing ecosystem: a
mesh-oriented substrate that helps people discover, trust, provision, operate,
and safely automate heterogeneous devices.

The name is provisional. It is memorable and fits Mycelium, but naming should
not dictate architecture or delay useful work.

This directory owns distribution integration, not component behavior. Each
project owns its contracts and documentation. The strategy documents below
explain how the projects fit together and how an open ecosystem can grow.

## Thesis

Software implementation is becoming cheaper. Durable value increasingly comes
from trusted interfaces, interoperability, distribution, operational knowledge,
and a community aligned around a shared substrate.

FPL should therefore make the foundational primitives easy to adopt, embed,
replace, and extend. It can build sustainable products and services through
stewardship, integration, certification, support, hosted operation, and selected
product-level commercial licensing.

## Documents

- [Ecosystem map](ecosystem.md) — project ownership, boundaries, and shared contracts.
- [Repository inventory](repository-inventory.md) — current GitHub ownership, visibility, and licenses.
- [Community and GTM](community-and-gtm.md) — who this is for and how adoption compounds.
- [Licensing](licensing.md) — a default licensing decision framework.

## Guardrails

- Open protocols and portable data before a vertically integrated suite.
- Each capability has one owning project; neighboring projects call it.
- Discovery reports availability, never authority.
- Deterministic operations with narrow, optional agent assistance.
- Local-first and self-hostable operation; hosted services are conveniences.
- Unix principals and standard operating-system controls remain first-class.
- A component must remain useful without the rest of the FPL ecosystem.
- Strategy documents describe direction; executable contracts remain authoritative.

## Near-term outcome

Prove one coherent journey on real mixed hardware:

1. Boot or install a node.
2. Establish its machine identity and enroll it safely.
3. Discover its topology, services, and resources.
4. Grant a person or workload least-privilege access.
5. Deliver signed software according to declared policy.
6. Observe health and security posture.
7. Remove or replace any individual control-plane component without rebuilding
   the fleet.

That journey is more useful than claiming to have built an all-encompassing OS.
