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

import java.util.Map;
import java.util.Optional;

/**
 * Encapsulates the various fields in a Http request that are required to perform SigV4 signing.
 */
public class RequestMetadata {

    /**
     * The full uri including the query string.
     * E.g. http://example.com:8182/sparql?query=queryString
     */
    private final String fullUri;

    /**
     * Http request method. "GET", "POST", "PUT" etc.
     */
    private final String method;
    /**
     * The payload of the request in bytes. This is usually set only for PUT or POST requests.
     */
    private final Optional<byte[]> content;
    /**
     * A map of headers in the request. Key - header name, value - header value.
     */
    private final Map<String, String> headers;
    /**
     * A map containing the query parameters as key, value.
     */
    private final Map<String, String> queryParameters;

    /**
     * Constructs an instance of Request metadata.
     * @param fullUri - the full URI. See {@link #fullUri}
     * @param method - the http request method. See {@link #method}
     * @param content - the payload of the http request. See {@link #content}
     * @param headers - the headers in the http request. See {@link #headers}
     * @param queryParameters - the query parameters. See {@link #headers}
     */
    public RequestMetadata(final String fullUri, final String method, final Optional<byte[]> content,
                           final Map<String, String> headers, final Map<String, String> queryParameters) {
        this.fullUri = fullUri;
        this.method = method;
        this.content = content;
        this.headers = headers;
        this.queryParameters = queryParameters;
    }

    /**
     * @return the fillURI set in the request metadata.
     */
    public String getFullUri() {
        return fullUri;
    }

    /**
     * @return the method set in the request metadata.
     */
    public String getMethod() {
        return method;
    }

    /**
     * @return content in the request metadata.
     */
    public Optional<byte[]> getContent() {
        return content;
    }

    /**
     * @return the headers in the request metadata.
     */
    public Map<String, String> getHeaders() {
        return headers;
    }

    /**
     * @return the query parameters map in the request metadata.
     */
    public Map<String, String> getQueryParameters() {
        return queryParameters;
    }
}
