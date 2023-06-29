# optee TA and REE application to support fde on Ubuntu Core

This repository contains the REE/host and TA to handle sealing and unsealing
of the keys used for the fde on Ubuntu Core systems [2].
Host application is expected to be invoked by snapd/snap bootstrap
within Ubuntu Core runtime.
REE application assumes tee kernel driver is either already loaded
or statically built into the kernel.
Passed keys are encrypted with HUK derived key. Each TA has own derived key,
which is further derived by randomised handle generated at key sealing.

REE application and TA assume optee version 3.12+  [1]

There 3 scenarios for host binary to be executed in.

## During system install: executable `fde-setup`
This hook can be executed either as kernel snap hook in snap environment or
as hook within initramfs runtime.
When running as kernel snap hook, operation to be performed is requested
from`snapctl` with parameter `fde-setup-request`. Returned request is json
formatted string. Result of the operation is passed back to `snapctl` as json
formatted sting with parameter `fde-setup-result`.
When running within initramfs runtime. Operation to be performed is passed as
json formated string on stdin. Result of the operation is returned
as json formatted string on stdout.
* supported operations:
  * initial-setup: encrypt passed key, generate handle is supported.
    * request: `{"op": "initial-setup","key": "base64-encoded-bytes",
                     "key-name" : "string"}`
    * result: `{"encrypted-key": "base64-encoded-bytes",
               "handle": "<base64-generated-bytes>"}`

## Within initrd: executable `fde-reveal-key`
Operation to be performed is passed as json formated string on stdin. Result
of the operation is returned as json formatted string on stdout.
* supported operations:
  * reveal: reveal key from passed
    * request: `{ "op": "reveal", "sealed-key": "base64-encoded-bytes",
                 "handle": "base64-encoded-bytes", "sealed-key-name": "string"}`
    * result: `{"key": "base64 encoded key"}`
  * lock: lock interface till next reboot
    * request: `{ "op": "lock" }`
    * result:

## Testing
* --ta-lock-status: get TA lock status
* --lock-ta: lock TA for any crypto operation till next reboot
* --generate-random:

## Acronyms:
* REE: Rich Execution Environment
* TA: Trusted Application
* HUK: Hardware Unique Key

[1]: https://github.com/OP-TEE/optee_os
[2]: https://ubuntu.com/core
