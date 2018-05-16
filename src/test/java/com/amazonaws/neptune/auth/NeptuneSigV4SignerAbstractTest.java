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
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.internal.SignerConstants;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;

/**
 * Defines the basic set of tests that each signer implementation should pass.
 * @param <T> the type of the request object for the implemented signer class.
 */
@Ignore
public abstract class NeptuneSigV4SignerAbstractTest<T> {

    protected static final String HEADER_ONE_NAME = "header1";
    protected static final String HEADER_ONE_VALUE = "value1";
    protected static final String HEADER_TWO_NAME = "header2";
    protected static final String HEADER_TWO_VALUE = "value2";
    protected static final String HOST_HEADER_NAME = "host";
    protected static final String TEST_REQUEST_PATH = "/path/test";
    protected static final String TEST_REQUEST_PATH_WITH_SLASH = TEST_REQUEST_PATH + "/";
    protected static final String TEST_HOST_NAME = "example.com";
    protected static final String TEST_PORT = "8182";
    protected static final String TEST_ENDPOINT = TEST_HOST_NAME + ":" + TEST_PORT;
    protected static final String TEST_ENDPOINT_URI = "http://" + TEST_ENDPOINT;
    protected static final String TEST_FULL_URI = TEST_ENDPOINT_URI + TEST_REQUEST_PATH;
    protected static final String TEST_FULL_URI_WITH_SLASH = TEST_ENDPOINT_URI + TEST_REQUEST_PATH_WITH_SLASH;
    protected static final String TEST_REGION = "us-east-1";
    protected static final String TEST_SPARQL_QUERY = "select * from {?s ?p ?o}";
    protected static final String HTTP_GET = "GET";
    protected static final String HTTP_POST = "POST";
    protected static final String TEST_QUERY_PARAM_NAME = "query";
    protected static final String TEST_DATE_HEADER_VALUE = "2020/10/04";
    protected static final String TEST_AUTHORIZATION_HEADER_VALUE = "Authorization Header";

    protected final AWSCredentialsProvider awsCredentialsProvider = mock(AWSCredentialsProvider.class);

    private NeptuneSigV4SignerBase<T> signer;

    @Before
    public void setup() {
        signer = getSigner();
    }

    abstract protected NeptuneSigV4SignerBase<T> getSigner();

    abstract protected T createGetRequest(final String fullURI,
            final Map<String, String> expectedHeaders);

    abstract protected T createPostRequest(final String fullURI,
            final Map<String, String> expectedHeaders,
            final String payload);

    abstract protected Map<String, String> getRequestHeaders(final T request);

    @Test
    public void toSignableRequestHappyGet() throws Exception {

        // prep
        final String uri = TEST_FULL_URI;
        final Map<String, String> requestHeaders = new HashMap<>();
        requestHeaders.put(HEADER_ONE_NAME, HEADER_ONE_VALUE);
        requestHeaders.put(HEADER_TWO_NAME, HEADER_TWO_VALUE);
        requestHeaders.put(HOST_HEADER_NAME, TEST_ENDPOINT);

        final T request = createGetRequest(uri, requestHeaders);

        // call
        final SignableRequest signableRequest = signer.toSignableRequest(request);

        // verify
        final Map<String, List<String>> headers = signableRequest.getHeaders();
        assertEquals("Headers host size should be 2", 2, headers.size());
        assertEquals("Non host header should be retained", HEADER_ONE_VALUE, headers.get(HEADER_ONE_NAME));
        assertEquals("Non host header should be retained", HEADER_TWO_VALUE, headers.get(HEADER_TWO_NAME));
        assertEquals("Request content should be blank", "",
                IOUtils.toString(signableRequest.getContent(), StandardCharsets.UTF_8));
        assertEquals("Unexpected endpoint", URI.create(TEST_ENDPOINT_URI),
                signableRequest.getEndpoint());
        assertEquals("Unexpected resource path", TEST_REQUEST_PATH,
                signableRequest.getResourcePath());
    }

    @Test
    public void toSignableRequestHappyGetWithQuery() throws Exception {

        final String plainQuery = TEST_SPARQL_QUERY;
        final String encodedQuery = URLEncoder.encode(plainQuery, StandardCharsets.UTF_8.name());
        // prep
        final StringBuilder uriBuilder = new StringBuilder();
        uriBuilder.append(TEST_FULL_URI)
                .append("?")
                .append(TEST_QUERY_PARAM_NAME)
                .append("=")
                .append(encodedQuery);
        final String uri = uriBuilder.toString();
        final Map<String, String> requestHeaders = new HashMap<>();
        requestHeaders.put(HEADER_ONE_NAME, HEADER_ONE_VALUE);
        requestHeaders.put(HEADER_TWO_NAME, HEADER_TWO_VALUE);
        requestHeaders.put(HOST_HEADER_NAME, TEST_ENDPOINT);

        final T request = createGetRequest(uri, requestHeaders);

        // call
        final SignableRequest signableRequest = signer.toSignableRequest(request);

        // verify
        final Map<String, List<String>> headers = signableRequest.getHeaders();
        assertEquals("Headers host size should be 2", 2, headers.size());
        assertEquals("Non host header should be retained", HEADER_ONE_VALUE, headers.get(HEADER_ONE_NAME));
        assertEquals("Non host header should be retained", HEADER_TWO_VALUE, headers.get(HEADER_TWO_NAME));
        assertEquals("Unexpected endpoint", URI.create(TEST_ENDPOINT_URI),
                signableRequest.getEndpoint());
        assertEquals("Unexpected resource path", TEST_REQUEST_PATH,
                signableRequest.getResourcePath());

        final Map<String, List<String>> queryParams = signableRequest.getParameters();
        assertEquals("Unexpected query param", plainQuery,
                queryParams.get("query").get(0));
    }

    @Test
    public void toSignableRequestHappyPost() throws Exception {

        // prep
        final String uri = TEST_FULL_URI;
        final String requestBody = TEST_SPARQL_QUERY;
        final Map<String, String> requestHeaders = new HashMap<>();
        requestHeaders.put(HEADER_ONE_NAME, HEADER_ONE_VALUE);
        requestHeaders.put(HEADER_TWO_NAME, HEADER_TWO_VALUE);
        requestHeaders.put(HOST_HEADER_NAME, TEST_ENDPOINT);

        final T request = createPostRequest(uri, requestHeaders, requestBody);

        // call
        final SignableRequest signableRequest = signer.toSignableRequest(request);

        // verify
        final Map<String, List<String>> headers = signableRequest.getHeaders();
        assertEquals("Headers host size should be 2", 2, headers.size());
        assertEquals("Non host header should be retained", HEADER_ONE_VALUE, headers.get(HEADER_ONE_NAME));
        assertEquals("Non host header should be retained", HEADER_TWO_VALUE, headers.get(HEADER_TWO_NAME));
        assertEquals("", requestBody, IOUtils.toString(signableRequest.getContent(), StandardCharsets.UTF_8));
        assertEquals("Unexpected endpoint", URI.create(TEST_ENDPOINT_URI),
                signableRequest.getEndpoint());
        assertEquals("Unexpected resource path", TEST_REQUEST_PATH,
                signableRequest.getResourcePath());
    }


    @Test
    public void toSignableRequestHappyGetWithTrailingSlash() throws Exception {

        // prep
        final String uri = TEST_FULL_URI_WITH_SLASH;
        final Map<String, String> requestHeaders = new HashMap<>();
        requestHeaders.put(HEADER_ONE_NAME, HEADER_ONE_VALUE);
        requestHeaders.put(HEADER_TWO_NAME, HEADER_TWO_VALUE);
        requestHeaders.put(HOST_HEADER_NAME, TEST_ENDPOINT);

        final T request = createGetRequest(uri, requestHeaders);
        // call
        final SignableRequest signableRequest = signer.toSignableRequest(request);

        // verify
        final Map<String, List<String>> headers = signableRequest.getHeaders();
        assertEquals("Headers host size should be 2", 2, headers.size());
        assertEquals("Non host header should be retained", HEADER_ONE_VALUE, headers.get(HEADER_ONE_NAME));
        assertEquals("Non host header should be retained", HEADER_TWO_VALUE, headers.get(HEADER_TWO_NAME));
        assertEquals("Unexpected endpoint", URI.create(TEST_ENDPOINT_URI),
                signableRequest.getEndpoint());
        assertEquals("Unexpected resource path", TEST_REQUEST_PATH_WITH_SLASH,
                signableRequest.getResourcePath());
    }

    @Test(expected = NeptuneSigV4SignerException.class)
    public void toSignableRequestGetNoHost() throws NeptuneSigV4SignerException {

        // prep
        final String uri = TEST_REQUEST_PATH;
        final Map<String, String> requestHeaders = new HashMap<>();
        requestHeaders.put(HEADER_ONE_NAME, HEADER_ONE_VALUE);
        requestHeaders.put(HEADER_TWO_NAME, HEADER_TWO_VALUE);

        final T request = createGetRequest(uri, requestHeaders);
        // call
        signer.toSignableRequest(request);
    }

    @Test
    public void attachSignatureHeaders() throws Exception {

        // prep
        final String uri = TEST_FULL_URI_WITH_SLASH;
        final Map<String, String> requestHeaders = new HashMap<>();
        requestHeaders.put(HEADER_ONE_NAME, HEADER_ONE_VALUE);
        requestHeaders.put(HEADER_TWO_NAME, HEADER_TWO_VALUE);

        final T request = createGetRequest(uri, requestHeaders);

        final String hostname = TEST_HOST_NAME;
        final String dateHeader = TEST_DATE_HEADER_VALUE;
        final String authHeader = TEST_AUTHORIZATION_HEADER_VALUE;

        final NeptuneSigV4SignerBase.NeptuneSigV4Signature signature = new NeptuneSigV4SignerBase.NeptuneSigV4Signature(hostname, dateHeader, authHeader);
        signer.attachSignature(request, signature);

        final Map<String, String> attachedHeaders = getRequestHeaders(request);
        assertEquals(hostname, attachedHeaders.get(SignerConstants.HOST));
        assertEquals(dateHeader, attachedHeaders.get(SignerConstants.X_AMZ_DATE));
        assertEquals(HEADER_ONE_VALUE, attachedHeaders.get(HEADER_ONE_NAME));
        assertEquals(HEADER_TWO_VALUE, attachedHeaders.get(HEADER_TWO_NAME));
        assertEquals(authHeader, attachedHeaders.get(SignerConstants.AUTHORIZATION));
    }
}
