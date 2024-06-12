# Introduction

Simple Shamir's secret sharing implementation. Uses GF(256) to represent any single byte of the secret (255 bits). 
It means that for any byte of the secret, we generate separate polynomial with coeffients in GF(256).

Lagrange interpolation is used to recover a secret.
