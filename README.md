# Prime-order Elliptic Curve Groups

Package group exposes operations over prime-order elliptic curve groups and their scalars and elements, and implements 
the latest hash-to-curve specification to date (https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11).

The following table indexes supported groups with hash-to-curve capability and links each one to the underlying implementations:

| ID  | Name         | Implementation                |
|-----|--------------|-------------------------------|
| 1   | Ristretto255 | github.com/gtank/ristretto255 |
| 2   | Decaf448     | not yet supported             |
| 3   | P-256        | filippo.io/nistec             |
| 4   | P-384        | filippo.io/nistec             |
| 5   | P-521        | filippo.io/nistec             |
| 6   | Edwards25519 | filippo.io/edwards25519       |
| 7   | Edwards448   | not yet supported             |
