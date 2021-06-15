# Unikraft OpenSSL Test Application

This builds a Unikraft application image signing a message using the [Ed25519](https://ed25519.cr.yp.to/) implementation in OpenSSL.

## Dependencies

Apart from Unikraft, the following libraries / dependencies are required:
* `lib-pthread-embedded`
* `lib-newlib`
* `lib-lwip`
* `lib-openssl`

Use the `staging` branch for Unikraft and the libraries.

## Build

Dependencies have to be included in the order in the `Makefile`.
Update the `Makefile` variables (`UK_ROOT`, `UK_LIBS`, `LIBS`) according to your setup.

Configure the application via the configuration screen:
```
make menuconfig
```
The configuration is loaded from the `Config.uk` file.
As such, simply save the configuration and exit.

Build the application:
```
make
```
The first building of the application will take some time, as library files are downloaded, unpacked and built.
The resulting KVM image is `build/app-openssl_kvm-x86_64`.
The image name may be updated in the configuration screen (`make menuconfig`), using the `Image name` option.

## Run

Run the application in QEMU/KVM using the `qemu-guest` script (it's copied from the [kraft repositoriy](https://github.com/unikraft/kraft/blob/staging/scripts/qemu-guest)):
```
qemu-guest -k build/app-openssl_kvm-x86_64
```
The above command requires `root` (`sudo`) privileges.

The application (source code in `sign_ed25519.c`) signs the message in the `message_to_sign` buffer using the private key in the `private_key_buf` buffer.
For a simple OpenSSL test you can replace the `sign_ed25519.c` file in `Makefile.uk` with `version.c` and rebuild the app; this will print the OpenSSL version.
For a very simple test you can use the `empty_main.c` file in a similar manner.
