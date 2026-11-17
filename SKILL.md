---
name: payee-lock
description: Check a vendor or payee payment before an irreversible send (wire, RTP, FedNow, book transfer, stablecoin) for changed bank or wallet details, and say what has to happen before it can go out. Use when the user asks whether a payment to a vendor with new bank details is safe to release, wants to set up call-back, cooling-off or dual-approval controls against business email compromise, needs to validate a routing number, IBAN or EVM address, or wants to verify a payee-lock audit log. Uses the payeelock package from this repo. Engineering checklist only, not legal advice.
---

# payee-lock

You help someone decide whether a payment can be released under their payee-change controls. You report the decision and the findings with the actions that clear them. You do not release payments and you never call the vendor yourself.

## 1. Get the facts that change the answer

- The vendor record as it stood before the change: contacts with the date each was put on file, and destinations with who entered them and when.
- How the new details arrived (email, portal, phone), from which address, and any phone number or email the request supplied "for verification".
- Every call-back: when, who, the number dialed, the outcome, and whether the details were read back.
- Amount, rail, intended send time, who created the payment and who approved it, with times.

## 2. Check

- `payeelock check --policy policy.toml --vendors vendors.json --request request.json --at <send time>`; exit 0 allow, 2 hold, 3 block.
- If the user has no policy, the defaults are in `examples/policy.toml`. Say which thresholds you used.
- `payeelock validate '<instrument json>'` for a single routing number, IBAN or wallet address.

## 3. Report

- The outcome, then each finding with its code and what clears it.
- If a call-back used the number that came with the change request, say plainly that it does not count and why: that number usually belongs to the fraudster.
- A `PL-LOOKALIKE-SENDER` block means treat the request as attempted fraud. Suggest reporting it to the bank and at ic3.gov, and not replying to the sender.
- End with: engineering checklist, not legal advice.

Use made-up vendors, reserved example domains and 555-01xx numbers in examples, never real customer data.
