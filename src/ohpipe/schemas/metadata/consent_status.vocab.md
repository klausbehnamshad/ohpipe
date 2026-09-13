# Recommended Vocabulary: `consent_status`

**Status:** Informative (not normative at Core level).  
**Field:** `consent_status` — Block A, mandatory, free string in IMM-Core.  
**Version:** IMM-Core 1.0

---

## Background

IMM-Core does not enforce a `consent_status` enum because consent regimes differ across disciplines. Archival oral history, health research, migration sociology, and educational research each have distinct frameworks for what categories are relevant and how they are named. Importing one discipline's vocabulary under the banner of a "generic" core would falsely universalise it.

This file provides a cross-domain reference vocabulary. Implementation Profiles SHOULD specify a subset, an extension, or an alternative vocabulary appropriate to their disciplinary and legal context. A profile that does not specify an enum SHOULD reference this file.

---

## Cross-Domain Reference Vocabulary

| Term | Definition | Typical context |
|---|---|---|
| `research-only` | Interview may be used for academic research but not for teaching or public dissemination | Oral history, archival research |
| `teaching` | Interview may be used for academic research and anonymised teaching contexts | Oral history, education research |
| `public` | Interview may be used without restrictions on dissemination | Oral history (fully consented public deposit) |
| `embargoed` | Interview is under a time-limited embargo; access and use governed by embargo terms | Oral history, political history, sensitive biography |
| `broad-research` | Consent covers use across multiple research projects; not limited to the originating project | Health research, migration studies, social science panel data |
| `specific-project-only` | Consent is limited to the project in which the interview was originally conducted | Health research, clinical studies, single-project qualitative research |
| `withdrawn` | Participant has withdrawn consent; record retained for administrative purposes only — no substantive content accessible | Any discipline |

---

## Adoption by registered profiles

| Profile | Terms in use |
|---|---|
| IMM-Profile-LuxOH | `research-only` \| `teaching` \| `public` \| `embargoed` |
| IMM-Profile-Migration | `broad-research` \| `specific-project-only` \| `withdrawn` |

---

## Invariant rule

`withdrawn` MUST always be available as a valid value, even in profiles that specify a restricted enum. A withdrawn record MUST set `accessRights: "closed"`.

---

## Note on GDPR alignment

None of these terms maps 1:1 to a GDPR legal basis category. They describe what a participant consented to at the point of data collection, which is a layer above GDPR legal basis (typically Art. 6(1)(a) consent or Art. 9(2)(a) for sensitive data). Profiles targeting health research contexts should consider aligning with their national research ethics framework in addition to this vocabulary.
