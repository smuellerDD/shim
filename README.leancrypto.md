# Shim support with leancrypto

The leancrypto library offers PQC as well as composite PQC signature algorithms
that can be used by the Shim boot loader to verify the integrity of payload
data.

The leancrypto library is compiled separate from the Shim boot loader code.
During the linking of the Shim boot loader code, the leancrypto library is
added to Shim.

## Compilation of leancrypto

The leancrypto library build system allows the configuration of the library
to only build the functions required by the consumer. Furthermore, the
leancrypto library must be compiled for the EFI environment to work with
the Shim boot loader.

For the Shim boot loader, the following options generate an instance of
the leancrypto library which only offer:

* SHA2-256

* SHA2-512

* ML-DSA (all key sizes)

* SLH-DSA (all key sizes)

* Composite ML-DSA with ED25519 as well as ED448

```bash
meson setup build-shim \
 -Defi=enabled \
 -Dslh_dsa_ascon_128s=disabled -Dslh_dsa_ascon_128f=disabled \
 -Dascon=disabled -Dascon_keccak=disabled \
 -Dbike_5=disabled -Dbike_3=disabled -Dbike_1=disabled \
 -Dkyber_1024=disabled -Dkyber_768=disabled -Dkyber_512=disabled -Dkyber_x25519=disabled -Dkyber_x448=disabled \
 -Dhqc_256=disabled -Dhqc_192=disabled -Dhqc_128=disabled \
 -Dchacha20=disabled -Dchacha20poly1305=disabled \
 -Dchacha20_drng=disabled -Ddrbg_hash=disabled -Ddrbg_hmac=disabled -Dkmac_drng=disabled -Dcshake_drng=disabled \
 -Dhash_crypt=disabled -Dhmac=disabled -Dhkdf=disabled -Dkdf_ctr=disabled -Dkdf_fb=disabled -Dkdf_dpi=disabled -Dpbkdf2=disabled \
 -Dhotp=disabled -Dtotp=disabled \
 -Daes_block=disabled -Daes_cbc=disabled -Daes_ctr=disabled -Daes_kw=disabled -Dapps=disabled \
 -Dx509_generator=disabled \
 -Dpkcs7_generator=disabled
```

The following options can be added if SLH-DSA shall not be compiled

```bash
 -Dsphincs_shake_256s=disabled -Dsphincs_shake_256f=disabled \
 -Dsphincs_shake_192s=disabled -Dsphincs_shake_192f=disabled \
 -Dsphincs_shake_128s=disabled -Dsphincs_shake_128f=disabled \
```

The following options can be added if ML-DSA shall not be compiled

```bash
 -Ddilithium_87=disabled -Ddilithium_65=disabled -Ddilithium_44=disabled
```

The following options can be added if composite ML-DSA shall not be supported

```bash
 -Ddilithium_ed25519=disabled -Ddilithium_ed448=disabled
```

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
  
## Coexistance with OpenSSL

The cryptographic algorithms offered by the leancrypto library are used by
default even when OpenSSL offers the same algorithm implementation.

Only if an algorithm is not provided by OpenSSL (namely SHA-1 and RSA along
with the X509 support for RSA), OpenSSL is used.

Once it is deemed that SHA-1 and RSA are not necessary any more, the entire
OpenSSL code base can be removed for good from the Shim boot loader code base.
