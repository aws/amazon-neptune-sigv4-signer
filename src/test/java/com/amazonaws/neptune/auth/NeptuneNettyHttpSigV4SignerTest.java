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

import software.amazon.awssdk.http.ContentStreamProvider;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpVersion;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;

public class NeptuneNettyHttpSigV4SignerTest extends NeptuneSigV4SignerAbstractTest<FullHttpRequest> {

    private final NeptuneNettyHttpSigV4Signer signer;

    public NeptuneNettyHttpSigV4SignerTest() throws NeptuneSigV4SignerException {
        this.signer = new NeptuneNettyHttpSigV4Signer(TEST_REGION, awsCredentialsProvider);
    }

    @Override
    protected NeptuneSigV4SignerBase<FullHttpRequest> getSigner() {
        return signer;
    }

    @Override
    protected FullHttpRequest createGetRequest(final String fullURI, final Map<String, String> expectedHeaders) {
        final FullHttpRequest request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1,
                HttpMethod.GET,
                fullURI,
                Unpooled.buffer()
        );
        expectedHeaders.entrySet().forEach(entry -> request.headers().add(entry.getKey(), entry.getValue()));
        return request;
    }

    @Override
    protected FullHttpRequest createPostRequest(final String fullURI,
                                                final Map<String, String> expectedHeaders,
                                                final String payload) {
        final FullHttpRequest request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1,
                HttpMethod.POST,
                fullURI,
                Unpooled.copiedBuffer(payload.getBytes(StandardCharsets.UTF_8))
        );
        expectedHeaders.entrySet().forEach(entry -> request.headers().add(entry.getKey(), entry.getValue()));
        return request;
    }

    @Override
    protected Map<String, String> getRequestHeaders(FullHttpRequest request) {
        final Map<String, String> headers = new HashMap<>();
        request.headers().forEach(header -> headers.put(header.getKey(), header.getValue()));
        return headers;
    }

    @Test
    public void toSignableRequestNoHostInUri() throws Exception {
        final String uri = TEST_REQUEST_PATH_WITH_SLASH;
        String signableRequestBody = new String();

        final FullHttpRequest request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1,
                HttpMethod.GET,
                uri,
                Unpooled.buffer()
        );
        request.headers().add(HEADER_ONE_NAME, HEADER_ONE_VALUE);
        request.headers().add(HEADER_TWO_NAME, HEADER_TWO_VALUE);
        request.headers().add(HOST_HEADER_NAME, TEST_ENDPOINT);

        // call
        final SdkHttpFullRequest signableRequest = signer.toSignableRequest(request);

        // verification
        if(signableRequest.contentStreamProvider().isPresent()) {
                ContentStreamProvider csp = signableRequest.contentStreamProvider().get();
                signableRequestBody = new String(csp.newStream().readAllBytes(), StandardCharsets.UTF_8);
        }
        assertEquals("", signableRequestBody);
        assertEquals(URI.create(TEST_ENDPOINT_URI).getAuthority(), signableRequest.getUri().getAuthority());
        assertEquals(TEST_REQUEST_PATH_WITH_SLASH, signableRequest.encodedPath());
        Map<String, List<String>> headers = signableRequest.headers();
        assertEquals(2, headers.size());
        assertEquals(Arrays.asList(HEADER_ONE_VALUE), headers.get(HEADER_ONE_NAME));
        assertEquals(Arrays.asList(HEADER_TWO_VALUE), headers.get(HEADER_TWO_NAME));
    }
}
