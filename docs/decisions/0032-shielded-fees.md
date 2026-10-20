# Shielded fee reimbursement

Agave deducts ordinary transaction fees before executing a native instruction.
This iteration keeps that admission rule: a shared relay account fronts fees
and refundable staging rent. A V3 Orchard payment spends amount plus an exact,
publicly quoted fee from shielded notes, creates encrypted recipient/change
outputs and exposes only the fee as its positive public value balance. The
native finalizer pays that fee to the signed relay payee atomically with backing,
commitments, nullifiers and staging closure. No user fee key is used.

V3 has its own authorization domain, wire discriminator and feature activation.
It cannot simultaneously withdraw to a public recipient. Altering the fee,
payee, expiry or effects invalidates authorization. V1/V2 bytes and digests stay
unchanged. The existing patched Orchard circuit already proves value balance;
no new circuit or trusted setup is introduced.

The relay is a transport dependency, not a custodian of spending/viewing keys.
Its public key, fee, timing and IP/admission observations remain visible to the
relevant observers. A single pilot relay is not a decentralized relay market.
Failed/aborted submissions cost the relay, not the user's shielded balance;
strict durable quotas and a gross-debit cap bound that exposure. Only successful
payments reimburse it. Temporary staging rent is refunded to the relay and is
excluded from the user's quoted net fee. Permanent nullifier storage remains
part of the quote until a separate storage-economics change is reviewed.
