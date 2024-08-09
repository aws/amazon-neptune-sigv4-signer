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
        this.signer = new NeptuneJavaHttpSigV4Signer(NeptuneSigV4SignerAbstractTest.TEST_REGION, awsCredentialsProvider);
    }

    /**
     * Override this test to catch the expected exception differently given peculiarities of the Java HTTP client.
     */
    @Override
    public void toSignableRequestGetNoHost() throws NeptuneSigV4SignerException {
        // prep
        final String uri = TEST_REQUEST_PATH;
        final Map<String, String> requestHeaders = new HashMap<>();
        requestHeaders.put(HEADER_ONE_NAME, HEADER_ONE_VALUE);
        requestHeaders.put(HEADER_TWO_NAME, HEADER_TWO_VALUE);

        // test with no host will fail as part of the builder. this is validation built into the java client. that's
        // a bit different from the other clients, so catching the exception here and returning the expected error
        try {
            final HttpRequest.Builder request = createGetRequest(uri, requestHeaders);

            // call
            signer.toSignableRequest(request);
        } catch (IllegalArgumentException e) {
            throw new NeptuneSigV4SignerException("Failed to create request", e);
        }
    }

    @Override
    protected NeptuneSigV4SignerBase<HttpRequest.Builder> getSigner() {
        return signer;
    }

    @Override
    protected HttpRequest.Builder createGetRequest(final String fullURI, final Map<String, String> expectedHeaders) {
        final HttpRequest.Builder request = HttpRequest.newBuilder().
                GET().
                version(HttpClient.Version.HTTP_1_1).uri(URI.create(fullURI));
        expectedHeaders.entrySet().forEach(entry -> request.header(entry.getKey(), entry.getValue()));
        return request;
    }

    @Override
    protected HttpRequest.Builder createPostRequest(final String fullURI,
                                                    final Map<String, String> expectedHeaders,
                                                    final String payload) {
        final HttpRequest.Builder request = HttpRequest.newBuilder().
                POST(HttpRequest.BodyPublishers.ofByteArray(payload.getBytes(StandardCharsets.UTF_8))).
                version(HttpClient.Version.HTTP_1_1).uri(URI.create(fullURI));
        expectedHeaders.entrySet().forEach(entry -> request.header(entry.getKey(), entry.getValue()));
        return request;
    }

    @Override
    protected Map<String, String> getRequestHeaders(final HttpRequest.Builder request) {
        final Map<String, String> headers = new HashMap<>();
        request.build().headers().map().entrySet().forEach(header -> headers.put(header.getKey(), header.getValue().get(0)));
        return headers;
    }
}
