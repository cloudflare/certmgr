# showimp
## show imports

This will run over a source tree and print any imports that are not in
the standard library or inside the project.

```
kyle@nocturne:~/src/github.com/kisom/cryptutils$ showimp 
External imports:
        code.google.com/p/go.crypto/bcrypt
        code.google.com/p/go.crypto/nacl/box
        code.google.com/p/go.crypto/nacl/secretbox
        code.google.com/p/go.crypto/scrypt
        code.google.com/p/rsc/qr
        github.com/agl/ed25519
        github.com/conformal/yubikey
        github.com/gokyle/readpass
        github.com/gokyle/twofactor
        github.com/gorilla/mux
```

