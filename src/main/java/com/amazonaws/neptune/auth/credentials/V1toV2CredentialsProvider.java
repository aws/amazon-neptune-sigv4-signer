package com.amazonaws.neptune.auth.credentials;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSSessionCredentials;
import com.amazonaws.auth.AnonymousAWSCredentials;
import software.amazon.awssdk.auth.credentials.AnonymousCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;

public class V1toV2CredentialsProvider implements AwsCredentialsProvider {
    private final AWSCredentialsProvider v1CredentialsProvider;

    public static AwsCredentialsProvider create(final AWSCredentialsProvider v1CredentialsProvider) {
        return new V1toV2CredentialsProvider(v1CredentialsProvider);
    }

    private V1toV2CredentialsProvider(final AWSCredentialsProvider v1CredentialsProvider) {
        this.v1CredentialsProvider = v1CredentialsProvider;
    }

    @Override
    public AwsCredentials resolveCredentials() {
        final AWSCredentials v1Credentials = this.v1CredentialsProvider.getCredentials();

        if (v1Credentials instanceof AnonymousAWSCredentials) {
            return AnonymousCredentialsProvider.create().resolveCredentials();
        } else if (v1Credentials instanceof AWSSessionCredentials) {
            return AwsSessionCredentials.builder()
                    .accessKeyId(v1Credentials.getAWSAccessKeyId())
                    .secretAccessKey(v1Credentials.getAWSSecretKey())
                    .sessionToken(((AWSSessionCredentials) v1Credentials).getSessionToken())
                    .build();
        } else {
            return AwsBasicCredentials.create(v1Credentials.getAWSAccessKeyId(), v1Credentials.getAWSSecretKey());
        }
    }
}
