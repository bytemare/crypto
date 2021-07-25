// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

/*
Package cryptotools provides some abstract and easy-to-use interfaces to common cryptographic operations.

It enables using one interface for a variety of underlying primitives, and without the hassle of setting them up.

Available interfaces are:

- HashToGroup: implementing hashing of arbitrary strings into prime-order groups, after hash-to-curve.

- Hash: interface to hashing primitives and exposing common functions such as hashing, hmac, HKDF, and expand-only HKDF.

- MHF: for memory hard function, a.k.a. password key derivation functions.

- Encoding: for encoding and decoding to and from different formats.

*/
package cryptotools
