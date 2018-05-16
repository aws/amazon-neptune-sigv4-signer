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

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;

public class NeptuneRequestMetadataSigV4SignerTest extends NeptuneSigV4SignerAbstractTest<RequestMetadata> {

    private final NeptuneRequestMetadataSigV4Signer signer;

    public NeptuneRequestMetadataSigV4SignerTest() throws NeptuneSigV4SignerException {
        this.signer = new NeptuneRequestMetadataSigV4Signer(TEST_REGION, awsCredentialsProvider);
    }

    @Override
    protected NeptuneSigV4SignerBase<RequestMetadata> getSigner() {
        return signer;
    }

    @Override
    protected RequestMetadata createGetRequest(String fullURI, Map<String, String> expectedHeaders) {
        return new RequestMetadata(fullURI, HTTP_GET, Optional.empty(), expectedHeaders, null);
    }

    @Override
    protected RequestMetadata createPostRequest(final String fullURI,
                                                final Map<String, String> expectedHeaders,
                                                final String payload) {
        return new RequestMetadata(fullURI, HTTP_POST,
                Optional.of(payload.getBytes(StandardCharsets.UTF_8)),
                expectedHeaders,
                null);
    }

    @Override
    protected Map<String, String> getRequestHeaders(final RequestMetadata request) {
        return request.getHeaders();
    }
}
