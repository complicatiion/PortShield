# Legal Notice

## Disclaimer

PortShield is provided **“as is”**, without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and non-infringement (see the MIT License in [LICENSE.md](LICENSE.md)).

To the extent permitted by applicable law, the author is not liable for any damages arising from the use of PortShield, including loss of network access, interrupted operation, failed updates, blocked or unblocked connections, or security incidents. Mandatory statutory liability (e.g. for intent or gross negligence, fraudulently concealed defects, or under product liability law) remains unaffected.

## Firewall changes

PortShield changes the Windows Firewall only after an explicit action of the user; bulk changes (adding programs, imports, rule sets) are listed in a review dialog first. Before deleting rules, imports, rule sets, whitelist mode, resets and restores, PortShield takes a snapshot (configurable). Please note:

- **Block always wins.** An allow rule cannot override a block rule of the Windows Firewall.
- **Kill switch and whitelist mode** can cut off network access completely – also remote desktop sessions when the LAN is not excluded.
- **Resetting the firewall** removes all own rules of the computer, not only PortShield's.
- **Group policies** of an organization take precedence. Local rules can be ignored by policy; changes to locally managed settings may only be made with the administrator's consent.
- **Other firewall products** may turn the Windows Firewall off; PortShield's rules then have no effect.
- PortShield does **not** inspect traffic and is **not** an antivirus product. A firewall rule restricts a program's network access; it does not make an untrusted program safe.

## Operator responsibility

The operator is responsible for the rules they create, change or delete, for the use of exports in other systems (group policy, Intune, security products) and for compliance with company policies and applicable law.

## Contact

Sven Klocke · sksdesign | complicatiion · [sksdesign.de](https://sksdesign.de)
