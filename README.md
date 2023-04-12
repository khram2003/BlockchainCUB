# RSA

## Key Generation
`./gradlew run --args="-c keys"`

## Encryption
`./gradlew run --args="input.txt output_encrypted.txt public.key -c encrypt"`

## Decryption
`./gradlew run --args="input_encrypted.txt output_decrypted.txt private.key -c decrypt"`