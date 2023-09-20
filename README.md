# Legacy Vault Example

This robot is an example that utilizes an extended version of the `Vault` library that allows for the use of a legacy SSL context. This is required in environments and robots that requires Python >=3.10 and OpenSSL 1.1.1 style renegotiation.

This example is particularly useful in situations where you want to use the `truststore` solution to inject OS certificates into your robot but your enterprise firewall will not allow connections and your robot fails with the error `UNSAFE_LEGACY_RENEGOTIATION_DISABLED`.