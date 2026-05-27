/*
 *   Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License").
 *   You may not use this file except in compliance with the License.
 *   A copy of the License is located at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   or in the "license" file accompanying this file. This file is distributed
 *   on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *   express or implied. See the License for the specific language governing
 *   permissions and limitations under the License.
 */

package com.amazonaws.neptune.auth;

import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpFullRequest;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpRequest;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Flow;

import static software.amazon.awssdk.http.auth.aws.signer.SignerConstant.AUTHORIZATION;
import static software.amazon.awssdk.http.auth.aws.signer.SignerConstant.HOST;
import static software.amazon.awssdk.http.auth.aws.signer.SignerConstant.X_AMZ_DATE;
import static software.amazon.awssdk.http.auth.aws.signer.SignerConstant.X_AMZ_SECURITY_TOKEN;

/**
 * Signer for HTTP requests made via {@code java.net.http} {@link HttpRequest}s.
 * <p>
 * This signer operates on {@link HttpRequest.Builder} instances. After calling
 * {@link #signRequest(HttpRequest.Builder)}, the builder will have the necessary
 * SigV4 authentication headers attached. Call {@code builder.build()} to obtain
 * the signed {@link HttpRequest}.
 * <p>
 * <b>Important:</b> The JVM restricts setting the {@code Host} header on
 * {@code java.net.http.HttpRequest} by default. If you need to set it explicitly,
 * launch the JVM with {@code -Djdk.httpclient.allowRestrictedHeaders=host}.
 */
public class NeptuneJavaHttpSigV4Signer extends NeptuneSigV4SignerBase<HttpRequest.Builder> {

    /**
     * Create a V4 Signer for {@code java.net.http} HTTP requests.
     *
     * @param regionName             name of the region for which the request is signed
     * @param awsCredentialsProvider the provider offering access to the credentials used for signing the request
     * @throws NeptuneSigV4SignerException in case initialization fails
     */
    public NeptuneJavaHttpSigV4Signer(final String regionName,
                                      final AwsCredentialsProvider awsCredentialsProvider)
            throws NeptuneSigV4SignerException {
        super(regionName, awsCredentialsProvider);
    }

    /**
     * Create a V4 Signer for {@code java.net.http} HTTP requests.
     *
     * @param regionName             name of the region for which the request is signed
     * @param awsCredentialsProvider the provider offering access to the credentials used for signing the request
     * @param serviceName            name of the service name used to sign the requests
     * @throws NeptuneSigV4SignerException in case initialization fails
     */
    public NeptuneJavaHttpSigV4Signer(final String regionName,
                                      final AwsCredentialsProvider awsCredentialsProvider,
                                      final String serviceName)
            throws NeptuneSigV4SignerException {
        super(regionName, awsCredentialsProvider, serviceName);
    }

    @Override
    protected SdkHttpFullRequest toSignableRequest(final HttpRequest.Builder requestBuilder)
            throws NeptuneSigV4SignerException {

        final HttpRequest request = requestBuilder.build();

        checkNotNull(request, "The request must not be null");
        checkNotNull(request.uri(), "The request URI must not be null");
        checkNotNull(request.method(), "The request method must not be null");

        // Convert headers, skipping Host (the signer adds it)
        final Map<String, List<String>> headersInternal = new HashMap<>();
        for (final Map.Entry<String, List<String>> entry : request.headers().map().entrySet()) {
            if (!entry.getKey().equalsIgnoreCase(HOST)) {
                headersInternal.put(entry.getKey(), entry.getValue());
            }
        }

        // Extract query parameters
        final URI uri = request.uri();
        final Map<String, List<String>> parametersInternal = extractParametersFromQueryString(uri.getRawQuery());

        // Extract body content
        final InputStream content;
        if (request.bodyPublisher().isPresent()) {
            content = new ByteArrayInputStream(collectBodyBytes(request.bodyPublisher().get()));
        } else {
            content = new ByteArrayInputStream(new byte[0]);
        }

        // Build endpoint URI
        if (uri.getHost() == null) {
            throw new NeptuneSigV4SignerException(
                    "Unable to extract host information from the request URI, required for SigV4 signing: " + uri);
        }
        final URI endpoint = URI.create(uri.getScheme() + "://" + uri.getAuthority());

        return convertToSignableRequest(
                request.method(),
                endpoint,
                uri.getPath(),
                headersInternal,
                parametersInternal,
                content);
    }

    @Override
    protected void attachSignature(final HttpRequest.Builder request, final NeptuneSigV4Signature signature)
            throws NeptuneSigV4SignerException {

        checkNotNull(signature, "The signature must not be null");
        checkNotNull(signature.getHostHeader(), "The signed Host header must not be null");
        checkNotNull(signature.getXAmzDateHeader(), "The signed X-AMZ-DATE header must not be null");
        checkNotNull(signature.getAuthorizationHeader(), "The signed Authorization header must not be null");

        request.setHeader(HOST, signature.getHostHeader());
        request.setHeader(X_AMZ_DATE, signature.getXAmzDateHeader());
        request.setHeader(AUTHORIZATION, signature.getAuthorizationHeader());

        if (!signature.getSessionToken().isEmpty()) {
            request.setHeader(X_AMZ_SECURITY_TOKEN, signature.getSessionToken());
        }
    }

    /**
     * Collects all bytes from a {@link HttpRequest.BodyPublisher} synchronously.
     * This works correctly for standard body publishers (ofString, ofByteArray, ofInputStream)
     * which publish their content immediately upon subscription.
     */
    private static byte[] collectBodyBytes(final HttpRequest.BodyPublisher publisher) throws NeptuneSigV4SignerException {
        final List<ByteBuffer> buffers = new ArrayList<>();
        final CountDownLatch latch = new CountDownLatch(1);
        final Throwable[] error = new Throwable[1];

        publisher.subscribe(new Flow.Subscriber<>() {
            @Override
            public void onSubscribe(Flow.Subscription subscription) {
                subscription.request(Long.MAX_VALUE);
            }

            @Override
            public void onNext(ByteBuffer item) {
                byte[] bytes = new byte[item.remaining()];
                item.get(bytes);
                buffers.add(ByteBuffer.wrap(bytes));
            }

            @Override
            public void onError(Throwable throwable) {
                error[0] = throwable;
                latch.countDown();
            }

            @Override
            public void onComplete() {
                latch.countDown();
            }
        });

        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new NeptuneSigV4SignerException("Interrupted while reading request body", e);
        }

        if (error[0] != null) {
            throw new NeptuneSigV4SignerException("Error reading request body", error[0]);
        }

        int totalSize = buffers.stream().mapToInt(ByteBuffer::remaining).sum();
        byte[] result = new byte[totalSize];
        int offset = 0;
        for (ByteBuffer buf : buffers) {
            int len = buf.remaining();
            buf.get(result, offset, len);
            offset += len;
        }
        return result;
    }
}
