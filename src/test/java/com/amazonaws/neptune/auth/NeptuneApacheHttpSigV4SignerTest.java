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

import com.amazonaws.SignableRequest;
import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestWrapper;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.StringEntity;
import org.junit.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;


public class NeptuneApacheHttpSigV4SignerTest extends NeptuneSigV4SignerAbstractTest<HttpUriRequest> {

   private NeptuneApacheHttpSigV4Signer signer;

    public NeptuneApacheHttpSigV4SignerTest() throws NeptuneSigV4SignerException {
        this.signer = new NeptuneApacheHttpSigV4Signer(TEST_REGION, awsCredentialsProvider);
    }

    @Test
    public void toSignableRequestHappyWithWrapper() throws NeptuneSigV4SignerException {

        // prep
        final URI uri = URI.create(TEST_REQUEST_PATH);
        final HttpGet request = new HttpGet(uri);
        request.setHeader(HEADER_ONE_NAME, HEADER_ONE_VALUE);
        request.setHeader(HEADER_TWO_NAME, HEADER_TWO_VALUE);
        request.setHeader(HOST_HEADER_NAME, TEST_ENDPOINT);

        final HttpHost httpHost = new HttpHost(TEST_HOST_NAME, Integer.valueOf(TEST_PORT), HttpHost.DEFAULT_SCHEME_NAME);
        final HttpRequestWrapper wrapper = HttpRequestWrapper.wrap(request, httpHost);

        // call
        final SignableRequest signableRequest = signer.toSignableRequest(wrapper);

        // verify
        Map<String, List<String>> headers = signableRequest.getHeaders();
        assertEquals("Headers host size should be 2", 2, headers.size());
        assertEquals("Non host header should be retained", HEADER_ONE_VALUE, headers.get(HEADER_ONE_NAME));
        assertEquals("Non host header should be retained", HEADER_TWO_VALUE, headers.get(HEADER_TWO_NAME));
        assertEquals("Endpoint returned is not as expected", URI.create(TEST_ENDPOINT_URI),
                signableRequest.getEndpoint());
        assertEquals("Resource returned is not as expected", TEST_REQUEST_PATH,
                signableRequest.getResourcePath());
    }

    @Override
    public NeptuneApacheHttpSigV4Signer getSigner() {
        return signer;
    }

    @Override
    protected HttpUriRequest createGetRequest(final String fullURI, final Map<String, String> expectedHeaders) {
        final HttpUriRequest request = new HttpGet(URI.create(fullURI));
        expectedHeaders.entrySet().forEach(entry -> request.setHeader(entry.getKey(), entry.getValue()));
        return request;
    }

    @Override
    protected HttpUriRequest createPostRequest(final String fullURI,
                                               final Map<String, String> expectedHeaders,
                                               final String payload) {
        final HttpPost request = new HttpPost(URI.create(fullURI));
        expectedHeaders.entrySet().forEach(entry -> request.setHeader(entry.getKey(), entry.getValue()));
        request.setEntity(new StringEntity(payload, StandardCharsets.UTF_8));
        return request;
    }

    @Override
    protected Map<String, String> getRequestHeaders(final HttpUriRequest request) {
        return Arrays.stream(request.getAllHeaders()).collect(Collectors.toMap(Header::getName, Header::getValue));
    }
}
