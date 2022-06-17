## Amazon Neptune SigV4 Signer

A library for sending AWS Signature Version 4 signed requests over HTTP to [Amazon Neptune](https://aws.amazon.com/neptune). This package provides signers that can be used with various implementations of HttpRequests:

1. [NeptuneApacheHttpSigV4Signer.java](https://github.com/aws/amazon-neptune-sigv4-signer/blob/master/src/main/java/com/amazonaws/neptune/auth/NeptuneApacheHttpSigV4Signer.java) - provides an implementation for signing Apache Http Requests.
2. [NeptuneNettyHttpSigV4Signer.java](https://github.com/aws/amazon-neptune-sigv4-signer/blob/master/src/main/java/com/amazonaws/neptune/auth/NeptuneNettyHttpSigV4Signer.java) - provides an implementation for signing Netty Http requests
3. [NeptuneRequestMetadataSigV4Signer.java](https://github.com/aws/amazon-neptune-sigv4-signer/blob/master/src/main/java/com/amazonaws/neptune/auth/NeptuneRequestMetadataSigV4Signer.java) - provides an implementation for a generic Request object RequestMetadata. A user of this class can convert their native HttpRequest into a RequestMetadata object and pass it to this class to create the signature.
 
For examples of usage of this library refer to:

1. [Connecting to Neptune Using Java and Gremlin with Signature Version 4 Signing](https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth-connecting-gremlin-java.html)
2. [amazon-neptune-sparql-java-sigv4](https://github.com/aws/amazon-neptune-sparql-java-sigv4)  - Contains examples for sending SigV4 signed requests with Apache HttpUriRequest objects.
 
For more documentation around IAM database authentication for Neptune refer to [Identity and Access Management in Amazon Neptune](https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html)

For the official Amazon Neptune page refer to: https://aws.amazon.com/neptune

## License

This library is licensed under the Apache 2.0 License. 
