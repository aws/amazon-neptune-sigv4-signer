package com.amazonaws.neptune.auth.credentials;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSSessionCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.AnonymousAWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import org.junit.Test;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.identity.spi.AwsSessionCredentialsIdentity;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;


public class V1toV2CredentialsProviderTest {

    @Test
    public void testConversionOfCredentials() {
        final AWSCredentials credentials = new BasicAWSCredentials("accessKey", "SecretKey");
        final AWSCredentialsProvider v1CredentialProvider = buildV1CredentialsProvider(credentials);
        final AwsCredentialsProvider v2CredentialsProvider = V1toV2CredentialsProvider.create(v1CredentialProvider);

        // Assert
        assertV2Credentials(v2CredentialsProvider, credentials);
    }

    @Test
    public void testConversionOfSessionCredentials() {
        final AWSCredentials sessionCredentials = new BasicSessionCredentials("accessKey", "SecretKey", "sessionToken");
        final AWSCredentialsProvider v1CredentialProvider = buildV1CredentialsProvider(sessionCredentials);
        final AwsCredentialsProvider v2CredentialsProvider = V1toV2CredentialsProvider.create(v1CredentialProvider);

        // Assert
        assertV2Credentials(v2CredentialsProvider, sessionCredentials);
    }

    @Test
    public void testConversionOfAnonCredentials() {
        final AWSCredentials anonV1Credentials = new AnonymousAWSCredentials();
        final AWSCredentialsProvider v1CredentialProvider = buildV1CredentialsProvider(anonV1Credentials);
        final AwsCredentialsProvider v2CredentialsProvider = V1toV2CredentialsProvider.create(v1CredentialProvider);

        assertNotNull(v2CredentialsProvider);
        final AwsCredentials v2Credentials = v2CredentialsProvider.resolveCredentials();
        assertNotNull(v2Credentials);
        // AccessKey and secret key will be null for Anon Credentials
        assertNull(v2Credentials.accessKeyId());
        assertNull(v2Credentials.secretAccessKey());
    }

    private void assertV2Credentials(final AwsCredentialsProvider v2CredentialsProvider,
                                     final AWSCredentials expectedCredentials) {
        assertNotNull(v2CredentialsProvider);
        final AwsCredentials v2Credentials = v2CredentialsProvider.resolveCredentials();
        assertNotNull(v2Credentials);
        assertEquals(v2Credentials.accessKeyId(), expectedCredentials.getAWSAccessKeyId());
        assertEquals(v2Credentials.secretAccessKey(), expectedCredentials.getAWSSecretKey());
        if (expectedCredentials instanceof AWSSessionCredentials) {
            assertTrue(v2Credentials instanceof AwsSessionCredentialsIdentity);
            assertEquals(((AwsSessionCredentialsIdentity)v2Credentials).sessionToken(),
                    ((AWSSessionCredentials)expectedCredentials).getSessionToken());
        }
    }

    private static AWSCredentialsProvider buildV1CredentialsProvider(final AWSCredentials credentials) {
        return new AWSStaticCredentialsProvider(credentials);
    }
}
