# payee-lock

`payeelock` is a guard that runs just before an irreversible payment leaves: a wire, an RTP or FedNow credit, a book transfer, a stablecoin send. It compares the destination with the vendor master, and when the destination is new or recently changed it insists on three things before it will say `allow`:

1. a call-back to the vendor on a phone number or address that was **on file before the change**, with the new details read back;
2. a cooling-off period that grows with the amount;
3. two approvers, neither of whom created the payment or entered the new destination, above a threshold.

It also blocks look-alike sender domains, flags a destination that is already on file for another vendor, notices when a domestic vendor's money suddenly goes abroad, and writes every decision to a hash-chained audit log. It never sends money and never edits the vendor master.

Standard library only. Python 3.11+.

Built and maintained by Art Akopian, CEO of [Banrox](https://banrox.com). Banrox builds consumer credit and fraud-prevention software and publishes the general-purpose pieces.

> **Engineering checklist, not legal advice.** The guard enforces a process. It cannot tell whether the person who answered the call-back is really the vendor, and it does not decide who bears a loss. Liability for unauthorized and induced payments depends on UCC Article 4A, Regulation E where it applies, your account agreements and network rules.

## Why

Business email compromise is the second-largest loss category in the FBI's complaint data and it is mostly a payee-details problem. The 2025 IC3 annual report counts 24,768 BEC complaints with $3,046,598,558 in reported losses, up from 21,442 complaints and $2,770,151,146 in 2024 ([IC3 2025 Internet Crime Report](https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf), three-year comparison tables). The IC3 public service announcement of September 11, 2024 puts domestic and international exposed losses from October 2013 to December 2023 at $55,499,915,582 across 305,033 incidents, and its first prevention tip is to "use secondary channels and/or two-factor authentication to verify requests for changes in account information" ([I-091124-PSA](https://www.ic3.gov/PSA/2024/PSA240911)).

Instant rails remove the time that used to save some of these payments. The same IC3 report describes an Oregon city that lost over $6 million to a BEC wire; the bank was able to recall it only because the recipient account had been frozen after an earlier Financial Fraud Kill Chain request from a different victim, and the recipient bank called the originating bank. In 2025 the IC3 Recovery Asset Team froze $679,013,183 of $1,163,919,846 in attempted theft across 3,900 incidents (58%). A recall depends on the money still being there. On RTP and FedNow a credit is final once accepted and the receiver can move it on at once, so the check has to happen before the send, not after.

What the attack looks like, from the FinCEN advisories on email compromise ([FIN-2016-A003](https://www.fincen.gov/resources/advisories/fincen-advisory-fin-2016-a003), [FIN-2019-A005](https://www.fincen.gov/resources/advisories/fincen-advisory-fin-2019-a005)) and the IC3 PSA:

- A vendor's mailbox is compromised, or a look-alike domain is registered, and an email asks to "update our bank details" before the next invoice.
- The email gives a phone number "for verification". It is the fraudster's number.
- The new account is often at a different bank, sometimes in another country, sometimes a money-mule account that already received money from other victims.

Each control in `payeelock` answers one of those steps.

## Install

```sh
pip install git+https://github.com/BanroxArt/payee-lock
```

## Use

```sh
payeelock check --policy examples/policy.toml --vendors examples/vendors.json \
    --request examples/requests.json --log audit.jsonl
```

```
ALLOW  pay-001  v-100  ABA 011000015 acct ...7731  18,400.00 via rtp
HOLD   pay-002  v-100  ABA 021000021 acct ...0045  48,250.00 via wire
       hold   PL-COOLING-OFF: destination changed 5.8 hours ago; policy needs 48 for this amount
              -> wait until 2026-11-18T09:12:00+00:00
       hold   PL-CALLBACK-SUPPLIED-CONTACT: call-back cb-1 used the contact that came with the change request, not one on file
              -> repeat the call-back to a contact on file before the change
       hold   PL-DUAL-APPROVAL: needs 2 approvers other than the initiator and the person who entered the destination; has 0
              -> get the missing approvals after the request was created
BLOCK  pay-003  v-200  IBAN GB82...5432  9,120.00 via wire
       ...
       block  PL-LOOKALIKE-SENDER: payment request came from contoso-logistlcs.example, which resembles but is not contoso-logistics.example
```

Exit codes: 0 allow, 2 hold, 3 block, 1 bad input. A payment job can gate on the exit code alone. `--at` sets the intended send time (default: the request's `requested_at`).

```python
from payeelock import check, load, request_from, vendors_from

decision = check(load("policy.toml"), vendors_from(vendors_doc), request_from(request_doc), now)
if decision.outcome != "allow":
    for f in decision.findings:
        print(f.code, f.action, f.message, f.clears_by)
```

```sh
payeelock verify-log audit.jsonl          # exit 3 if any entry was edited, removed or reordered
payeelock validate '{"kind": "us_bank", "routing": "011000015", "account": "4402187731"}'
```

## Findings

| Code | Default | Fires when |
| --- | --- | --- |
| `PL-UNKNOWN-VENDOR` | block | The vendor id is not in the vendor master. |
| `PL-NO-CHANGE-RECORD` | hold | The destination is not on file and the request does not say how it arrived. |
| `PL-COOLING-OFF` | hold | A new or recent destination was received less than the policy's hours ago (24, 48 from $25,000, 72 from $100,000 by default). Advisory on rails not listed as irreversible. |
| `PL-CALLBACK-MISSING` | hold | New or recent destination (default: on file less than 30 days) with no call-back. |
| `PL-CALLBACK-SUPPLIED-CONTACT` | hold | The call-back went to the number or address that came with the change request. |
| `PL-CONTACT-RECENT` | hold | The contact dialed was itself put on file less than 30 days before the change. Fraudsters often change the phone number first. |
| `PL-CALLBACK-INVALID` | hold | Not confirmed, no read-back, older than 72 hours, before the change arrived, after the send time, or to a contact not on file. One valid call-back is enough. |
| `PL-LOOKALIKE-SENDER` | block | The payment or change request came from a domain within two edits of the vendor's, equal after folding `rn`/`m`, `0`/`o`, `1`/`l`, or containing the vendor's name as a label of another domain. |
| `PL-UNKNOWN-SENDER` | hold | A sender domain that is neither the vendor's nor a look-alike. |
| `PL-COUNTRY-CHANGE` | hold | A new or recent destination in a different country from the vendor's country on file. |
| `PL-SHARED-INSTRUMENT` | block | The destination is on file for another vendor too. |
| `PL-EVM-NO-CHECKSUM` | hold | A wallet address in a single case, so EIP-55 cannot catch a swapped character. |
| `PL-DUAL-APPROVAL` | hold | At or above $25,000 by default, fewer than two approvers dated between request creation and send, excluding the initiator and whoever entered the destination. |
| `PL-REVERSIBLE-RAIL` | info | The rail is not in `irreversible_rails`. The other findings still apply. |

The outcome is the worst action among the findings. Every action and threshold is set in [examples/policy.toml](examples/policy.toml). Unknown keys in the policy are an error, so a misspelt key cannot quietly turn a control off.

## Destinations

`us_bank` (ABA routing plus account, for ACH, wire, RTP and FedNow), `iban` (optional BIC, whose country must match) and `evm` (address plus EIP-155 chain id). Parsing checks the ABA check digit, the ISO 13616 length and mod-97 check, and the EIP-55 checksum. Keccak-256 is implemented in the package because `hashlib.sha3_256` uses the NIST padding and gives different digests; the tests check the sponge against `hashlib` with the NIST pad byte and against the ERC-20 event topics.

Destinations are compared by fingerprint, a SHA-256 of the normalized fields, so `GB82 WEST 1234 5698 7654 32` and `gb82west12345698765432` are the same destination and a one-digit change is not. The audit log stores the fingerprint and a masked form (`ABA 011000015 acct ...7731`), never the full account number.

## Audit log

JSON lines, each with the SHA-256 of the previous entry. `verify-log` reports the first line that was edited, removed or reordered. This makes tampering evident, it does not stop it: if the people who run payments can also rewrite the file, ship the head hash somewhere they cannot.

## What is real and what is not

Some claims about instant and tokenized payments circulate without a source. This package does not depend on any of them:

- **Instant credits are final.** That part is real. TCH's guidelines say RTP credit transfers "are irrevocable once sent to the RTP system and final when the message is accepted by the creditor FI", and that the receiving bank "has no obligation to return funds once an RTP payment is settled" ([RTP Request for Return of Funds guidelines](https://www.theclearinghouse.org/-/media/New/TCH/Documents/Payment-Systems/RTP_Request_for_Returns_v02-19-2021.pdf)). The sender can ask with a `camt.056`; FedNow has a return request message too ([FedNow fraud controls](https://explore.fednow.org/resources/fraud-at-a-glance.pdf)). Asking is all it is.
- **"Tokenized payments are push-only, so nobody can pull money from you."** Not true on public chains. ERC-20 `approve` and EIP-2612 `permit` let a third party pull tokens, and approval phishing is a large loss category. See the companion package approval-audit.
- **"Banks match SSN hashes when an account is linked, so a payment to the wrong John Doe is caught."** Partly. Early Warning, the operator of Zelle, sells an account-owner authentication service that compares the name, date of birth and SSN or tax ID a caller supplies with data contributed by banks ([Early Warning account validation ebook](https://www.earlywarning.com/sites/default/files/2021-06/Early%20Warning%20Account%20Validation%20eBook.pdf)). We found no primary source that it runs on every account link, that it works on SSN hashes, or that The Clearing House does the same. payee-lock compares destinations with your own vendor master and does not rely on a network-side identity check.
- **"A fraud flag follows the money to every downstream bank automatically."** Not today. RTP requires the sending participant to report fraud to TCH and the other participant with a `camt.056`, and FedNow requires fraud reporting to the service; the FBI's Financial Fraud Kill Chain reaches second-hop accounts only "if information is provided". None of that is an automatic freeze along the chain.

## Limits

- The guard trusts the call-back record. It checks that the number dialed was on file before the change; it cannot check that the call happened.
- The vendor master is the root of trust. If an attacker can edit it directly, the cooling-off period and the editor exclusion from approvals are what is left.
- Look-alike detection works on email domains only. It does not check display names or reply-to headers; feed it the address the request really came from.
- IBAN lengths are listed for 32 countries; others get the generic 15 to 34 check plus mod-97.
- No sanctions, OFAC or special-measures screening. Run that separately.

## Development

```sh
pip install -e '.[dev]'
ruff check . && ruff format --check . && python scripts/check.py && mypy && pytest -q
python bench/run.py
```

## License

MIT, copyright 2026 Banrox Inc.
