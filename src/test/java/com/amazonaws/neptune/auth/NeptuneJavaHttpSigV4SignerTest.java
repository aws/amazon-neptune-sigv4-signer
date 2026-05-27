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

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class NeptuneJavaHttpSigV4SignerTest extends NeptuneSigV4SignerAbstractTest<HttpRequest.Builder> {

    private final NeptuneJavaHttpSigV4Signer signer;

    public NeptuneJavaHttpSigV4SignerTest() throws NeptuneSigV4SignerException {
        this.signer = new NeptuneJavaHttpSigV4Signer(TEST_REGION, awsCredentialsProvider);
    }

    @Override
    protected NeptuneSigV4SignerBase<HttpRequest.Builder> getSigner() {
        return signer;
    }

    @Override
    protected HttpRequest.Builder createGetRequest(final String fullURI, final Map<String, String> expectedHeaders) {
        final HttpRequest.Builder builder = HttpRequest.newBuilder()
                .GET()
                .version(HttpClient.Version.HTTP_1_1)
                .uri(URI.create(fullURI));
        expectedHeaders.forEach(builder::header);
        return builder;
    }

    @Override
    protected HttpRequest.Builder createPostRequest(final String fullURI,
                                                    final Map<String, String> expectedHeaders,
                                                    final String payload) {
        final HttpRequest.Builder builder = HttpRequest.newBuilder()
                .POST(HttpRequest.BodyPublishers.ofByteArray(payload.getBytes(StandardCharsets.UTF_8)))
                .version(HttpClient.Version.HTTP_1_1)
                .uri(URI.create(fullURI));
        expectedHeaders.forEach(builder::header);
        return builder;
    }

    @Override
    protected Map<String, String> getRequestHeaders(final HttpRequest.Builder requestBuilder) {
        final Map<String, String> headers = new HashMap<>();
        requestBuilder.build().headers().map().forEach((k, v) -> headers.put(k, v.get(0)));
        return headers;
    }

    /**
     * Override: java.net.http validates URIs eagerly — a relative path without host
     * throws IllegalArgumentException at URI.create() time, not during signing.
     */
    @Override
    public void toSignableRequestGetNoHost() throws NeptuneSigV4SignerException {
        final String uri = TEST_REQUEST_PATH;
        final Map<String, String> requestHeaders = new HashMap<>();
        requestHeaders.put(HEADER_ONE_NAME, HEADER_ONE_VALUE);
        requestHeaders.put(HEADER_TWO_NAME, HEADER_TWO_VALUE);

        try {
            final HttpRequest.Builder request = createGetRequest(uri, requestHeaders);
            signer.toSignableRequest(request);
        } catch (IllegalArgumentException e) {
            throw new NeptuneSigV4SignerException("URI validation failed", e);
        }
    }
}
