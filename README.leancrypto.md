# Shim support with leancrypto

The leancrypto library offers PQC as well as composite PQC signature algorithms
that can be used by the Shim boot loader to verify the integrity of payload
data.

The leancrypto library is compiled separate from the Shim boot loader code.
During the linking of the Shim boot loader code, the leancrypto library is
added to Shim.

## Quick Start

Do the following:

1. copy / unpack the leancrypto source code into the shim bootloader
source code root directory into the `leancrypto` directory.

2. invoke `leancrypto/build-scripts/shim_support.sh leancrypt` to generate
the build directory of leancrypto of `leancrypto-build-shim`.

3. compile leancrypto: `meson compile -C leancrypto-build-shim`

4. optional, if no leancrypto header files are installed - if you have the
   header files installed either via your distribution, or via a general local
   build, skip this step: `sudo meson install -C leancrypto-build-shim`

4. compile shim: `make`

## Details for Compilation of leancrypto

NOTE: This section is only of interest if you want to know more than what
is outlined in the Quick Start section.

The leancrypto library build system allows the configuration of the library
to only build the functions required by the consumer. Furthermore, the
leancrypto library must be compiled for the EFI environment to work with
the Shim boot loader.

For the Shim boot loader, the following options generate an instance of
the leancrypto library which only offers:

* SHA2-256

* SHA2-512

* ML-DSA (all key sizes)

* SLH-DSA (all key sizes)

* Composite ML-DSA with ED25519 as well as ED448

NOTE: The tool used for signing the kernel referenced in
`mkosi/mkosi.finalize`, `ukify`, links with OpenSSL to sign the data.
As OpenSSL only supports ML-DSA, SLH-DSA as well as the composite
signatures would not be used. Once `ukify` would be updated to link
with leancrypto, the other signature types can be used.

```bash
build-scripts/shim_support.sh
```

The following options can be added in the mentioned script if SLH-DSA
shall not be compiled

```bash
 -Dsphincs_shake_256s=disabled -Dsphincs_shake_256f=disabled \
 -Dsphincs_shake_192s=disabled -Dsphincs_shake_192f=disabled \
 -Dsphincs_shake_128s=disabled -Dsphincs_shake_128f=disabled \
```

The following options can be added in the mentioned script if ML-DSA
shall not be compiled

```bash
 -Ddilithium_87=disabled -Ddilithium_65=disabled -Ddilithium_44=disabled
```

The following options can be added in the mentioned script if composite
ML-DSA shall not be supported

```bash
 -Ddilithium_ed25519=disabled -Ddilithium_ed448=disabled
```

Note: The mentioned options must be set during the invocation of `meson setup`
because some options create header files which must not be present if an option
is deselected. Thus, if you disable the mentioned options with `meson configure`
the initially created header files are not removed and compilation breaks.

After the configuration step, the following command builds the leancrypto
static library: `meson compile -C build-shim`. Note, as the EFI target is built,
no test scripts are built during the compile process as they would not be able
to be run anyways. If you want to test the leancrypto functionality, you need
to invoke the aforementioned configuration command *without* the option
`-Defi=enabled`. This compilation generates all relevant test code that can
be executed with `meson test -C build-shim` on the build system.

The compilation yields the file `build-shim/libleancrypto.a` which has to be
linked with Shim.

The compiled binary contains all accelerated implementations of the respective
cryptographic algorithms which are automatically enabled.

## Compiling Shim with leancrypto

The standard header files installed as part of the regular compilation process
can also be used for building with Shim.

Note, this implies that the respective include directory needs to be pointed
to with CFLAGS as follows:

```
CFLAGS += -I/usr/local/include -DLC_EFI_ENVIRONMENT
```

## Linking with Shim

Once leancrypto is compiled, the resulting `libleancrypto.a` needs to be linked
with the Shim boot loader code. This is achieved by pointing to that file from
the following files:

* Make.defaults: The variable `EFI_LIBS` needs to be extended to point to the
  `libeancrypto.a` file between the start-group and end-group markers
  
* Makefile: The variable `LIBS` need to be extended to also point to the
  `libleancrypto.a` file.

NOTE: By default, both try to find `libleancrypto.a` in the directory `Cryptlib`.
Thus, simply copy from the leancrypto tree `build-shim/libleancrypto.a` to
`Cryptlib`.
  
## Coexistance with OpenSSL

The cryptographic algorithms offered by the leancrypto library are used by
default even when OpenSSL offers the same algorithm implementation.

Only if an algorithm is not provided by leancrypto (namely SHA-1 and RSA along
with the X509 support for RSA), OpenSSL is used.

Once it is deemed that SHA-1 and RSA are not necessary any more, the entire
OpenSSL code base can be removed for good from the Shim boot loader code base.

# NOTES

Shim should be compiled with -z noexecstack to remove the following warning:
`ld: warning: dilithium_shuffle_avx2.S.o: missing .note.GNU-stack section implies executable stack`
