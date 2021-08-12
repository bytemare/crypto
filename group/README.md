# Prime-order Elliptic Curve Groups

Package group exposes operations over prime-order elliptic curve groups and their scalars and elements, and implements 
the latest hash-to-curve specification to date (https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11).

The following table indexes supported groups with hash-to-curve capability and links each one to the underlying implementations:

| ID | Name | Production ready | Implementation | 
|--:	|--:	|---	|---	| 
| 1 | Ristretto255 | n/a | github.com/gtank/ristretto255 | 
| 2 | Decaf448 | n/a | n/a | 
| 3 | P-256 | n/a | github.com/armfazh/h2c-go-ref | 
| 4 | P-384 | n/a | github.com/armfazh/h2c-go-ref | 
| 5 | P-521 | n/a | github.com/armfazh/h2c-go-ref | 
| 6 | Curve25519 | n/a | filippo.io/edwards25519 | 
| 7 | Edwards25519 | n/a | filippo.io/edwards25519 | 
| 8 | Curve448 | n/a | github.com/armfazh/h2c-go-ref | 
| 9 | Edwards448 | n/a | github.com/armfazh/h2c-go-ref |
| 10 | Secp256k1 | n/a | github.com/armfazh/h2c-go-ref |

