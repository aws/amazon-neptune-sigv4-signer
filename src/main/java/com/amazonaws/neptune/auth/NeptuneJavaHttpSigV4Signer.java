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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Flow;

import static software.amazon.awssdk.http.auth.aws.internal.signer.util.SignerConstant.AUTHORIZATION;
import static software.amazon.awssdk.http.auth.aws.internal.signer.util.SignerConstant.HOST;
import static software.amazon.awssdk.http.auth.aws.internal.signer.util.SignerConstant.X_AMZ_DATE;
import static software.amazon.awssdk.http.auth.aws.internal.signer.util.SignerConstant.X_AMZ_SECURITY_TOKEN;

/**
 * Signer for HTTP requests made via java.net.* {@link HttpRequest}s.
 * <p>
 * Note that there are certain limitations for the usage of this class. In particular:
 * <ul>
 *     <li> The implementation adds a "Host" header. This may lead to problems if the original request has a host header
 *          with a name in different capitalization (e.g. "host"), leading to duplicate host headers and the signing
 *          process to fail. Hence, when using the API you need to make sure that there is either no host header in your
 *          original request or the host header uses the exact string "Host" as the header name.</li>
 *     <li> When using GET, the underlying HTTP request needs to encode whitespaces in query parameters using '%20'
 *          rather than (what most APIs such as the Apache commons {@link org.apache.http.client.utils.URIBuilder} do)
 *          using '+'.</li>
 * </ul>
 */
public class NeptuneJavaHttpSigV4Signer extends NeptuneSigV4SignerBase<HttpRequest.Builder> {

    /**
     * Create a V4 Signer for java.net.* HTTP requests.
     *
     * @param regionName             name of the region for which the request is signed
     * @param awsCredentialsProvider the provider offering access to the credentials used for signing the request
     * @throws NeptuneSigV4SignerException in case initialization fails
     */
    public NeptuneJavaHttpSigV4Signer(
            final String regionName, final AwsCredentialsProvider awsCredentialsProvider)
            throws NeptuneSigV4SignerException {

        super(regionName, awsCredentialsProvider);
    }

    @Override
    protected SdkHttpFullRequest toSignableRequest(final HttpRequest.Builder r)
            throws NeptuneSigV4SignerException {
        final HttpRequest request = r.build();

        // make sure the request is not null and contains the minimal required set of information
        checkNotNull(request, "The request must not be null");
        checkNotNull(request.uri(), "The request URI must not be null");
        checkNotNull(request.method(), "The request method must not be null");

        // convert the headers to the internal API format
        final HttpHeaders headers = request.headers();

        final Map<String, List<String>> headersInternal = new HashMap<>();
        for (final Map.Entry<String, List<String>> header : headers.map().entrySet()) {
            // Skip adding the Host header as the signing process will add one.
            if (!header.getKey().equalsIgnoreCase(HOST)) {
                headersInternal.put(header.getKey(), header.getValue());
            }
        }

        // convert the parameters to the internal API format
        final URI uri = request.uri();
        final String queryStr = uri.getRawQuery();
        final Map<String, List<String>> parametersInternal = extractParametersFromQueryString(queryStr);

        // carry over the entity (or an empty entity, if no entity is provided)
        final InputStream content;
        try {

            // if the request has a bodyPublisher then user it to set the content, otherwise set an empty string
            // for the content as per the SigV4 spec
            content = bodyPublisherToInputStream(request.bodyPublisher().
                    orElseGet(() -> HttpRequest.BodyPublishers.ofString("")));

        } catch (final IOException e) {

            throw new NeptuneSigV4SignerException("IOException while accessing entity content", e);

        }

        // http://example.com:8182 is the endpoint in http://example.com:8182/test/path
        URI endpoint;

        // /test/path is the resource path in http://example.com:8182/test/path
        String resourcePath;

        if (uri.getHost() != null) {
            endpoint = URI.create(uri.getScheme() + "://" + uri.getAuthority());
            resourcePath = uri.getPath();
        } else {
            throw new NeptuneSigV4SignerException(
                    "Unable to extract host information from the request uri, required for SigV4 signing: " + uri);
        }
        return convertToSignableRequest(
                request.method(),
                endpoint,
                resourcePath,
                headersInternal,
                parametersInternal,
                content);
    }

    @Override
    protected void attachSignature(final HttpRequest.Builder request, final NeptuneSigV4Signature signature)
            throws NeptuneSigV4SignerException {

        // make sure the request is not null and contains the minimal required set of information
        checkNotNull(signature, "The signature must not be null");
        checkNotNull(signature.getHostHeader(), "The signed Host header must not be null");
        checkNotNull(signature.getXAmzDateHeader(), "The signed X-AMZ-DATE header must not be null");
        checkNotNull(signature.getAuthorizationHeader(), "The signed Authorization header must not be null");

        request.setHeader(HOST, signature.getHostHeader());
        request.setHeader(X_AMZ_DATE, signature.getXAmzDateHeader());
        request.setHeader(AUTHORIZATION, signature.getAuthorizationHeader());

        // https://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html
        // For temporary security credentials, it requires an additional HTTP header
        // or query string parameter for the security token. The name of the header
        // or query string parameter is X-Amz-Security-Token, and the value is the session token.
        if (!signature.getSessionToken().isEmpty()) {
            request.setHeader(X_AMZ_SECURITY_TOKEN, signature.getSessionToken());
        }
    }

    public static InputStream bodyPublisherToInputStream(HttpRequest.BodyPublisher bodyPublisher) throws IOException {
        PipedInputStream pipedInputStream = new PipedInputStream();
        PipedOutputStream pipedOutputStream = new PipedOutputStream(pipedInputStream);
        bodyPublisher.subscribe(new OutputStreamSubscriber(pipedOutputStream));
        return pipedInputStream;
    }

    public static class OutputStreamSubscriber implements Flow.Subscriber<ByteBuffer> {
        private final OutputStream outputStream;
        private Flow.Subscription subscription;

        public OutputStreamSubscriber(OutputStream outputStream) {
            this.outputStream = outputStream;
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            this.subscription = subscription;
            subscription.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(ByteBuffer item) {
            try {
                byte[] bytes = new byte[item.remaining()];
                item.get(bytes);
                outputStream.write(bytes);
            } catch (IOException e) {
                subscription.cancel();
                throw new RuntimeException(e);
            }
        }

        @Override
        public void onError(Throwable throwable) {
            try {
                outputStream.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public void onComplete() {
            try {
                outputStream.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
