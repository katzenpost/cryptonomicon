# cryptonomicon

## Modular KEM double ratchet

[![Go Reference](https://pkg.go.dev/badge/github.com/katzenpost/cryptonomicon.svg)](https://pkg.go.dev/github.com/katzenpost/cryptonomicon)
[![Go Report Card](https://goreportcard.com/badge/github.com/katzenpost/cryptonomicon)](https://goreportcard.com/report/github.com/katzenpost/cryptonomicon)
[![CI](https://github.com/katzenpost/cryptonomicon/actions/workflows/linux.yml/badge.svg)](https://github.com/katzenpost/cryptonomicon/actions/workflows/linux.yml)



The KEM double ratchet's design is superior to the NIKE double ratchet; besides it being way better for composing fully hybrid post quantum ratchets, it achieves post compromise security in just 2 rounds.
Just because it uses a KEM doesn't mean you can't use a NIKE; as with Xwing, you can simply compose NIKEs as KEMs using an adhoc hashed ElGamal construction.

This modular KEM double ratchet design comes from the following 2020 paper: [The Double Ratchet: Security Notions, Proofs, and Modularization for the Signal Protocol](https://eprint.iacr.org/2018/1037)

Besides this implementation, my other contributions so far, are:

* [Nim language prototype of the modular KEM double ratchet](https://github.com/katzenpost/formal_specifications/blob/main/kem_ratchet/prototype/kem_double_ratchet/src/kem_double_ratchet.nim)

* [Partially written ProVerif model of the modular KEM double ratchet](https://github.com/katzenpost/formal_specifications/blob/main/kem_ratchet/kem_double_ratchet.pv)


## Status

It works. Although there's some more work to be done to make it "production ready" quality code.
In particular the current KEM double ratchet implementation does not remove the old instances of the FS AEAD and the `FS-Max` isn't enforced.


## Cryptography suite

This implementation of the modular KEM double ratchet uses the [hpqc](https://github.com/katzenpost/hpqc) cryptography library and thus has what is now known in modern parlance as "cryptographic agility" via golang interfaces. Thus, we can use *any* KEM with this KEM double ratchet and if you aren't completely satisfied any of the available KEMs then roll your own KEM. Combine your favorite classical NIKE with your favorite Post Quantum KEM if Xwing is not the hybrid KEM you are looking for:

```
	combiner.New(
		"MLKEM768-X448",
		[]kem.Scheme{
			adapter.FromNIKE(x448.Scheme(rand.Reader)),
			mlkem768.Scheme(),
		},
	),
```


## License

AGPLv3
