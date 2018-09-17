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
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.client.methods.HttpRequestWrapper;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.StringEntity;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.amazonaws.auth.internal.SignerConstants.AUTHORIZATION;
import static com.amazonaws.auth.internal.SignerConstants.HOST;
import static com.amazonaws.auth.internal.SignerConstants.X_AMZ_DATE;
import static com.amazonaws.auth.internal.SignerConstants.X_AMZ_SECURITY_TOKEN;

/**
 * Signer for HTTP requests made via Apache Commons {@link HttpUriRequest}s.
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
public class NeptuneApacheHttpSigV4Signer extends NeptuneSigV4SignerBase<HttpUriRequest> {

    /**
     * Create a V4 Signer for Apache Commons HTTP requests.
     *
     * @param regionName             name of the region for which the request is signed
     * @param awsCredentialsProvider the provider offering access to the credentials used for signing the request
     * @throws NeptuneSigV4SignerException in case initialization fails
     */
    public NeptuneApacheHttpSigV4Signer(
            final String regionName, final AWSCredentialsProvider awsCredentialsProvider)
            throws NeptuneSigV4SignerException {

        super(regionName, awsCredentialsProvider);
    }

    @Override
    protected SignableRequest<?> toSignableRequest(final HttpUriRequest request)
            throws NeptuneSigV4SignerException {

        // make sure the request is not null and contains the minimal required set of information
        checkNotNull(request, "The request must not be null");
        checkNotNull(request.getURI(), "The request URI must not be null");
        checkNotNull(request.getMethod(), "The request method must not be null");

        // convert the headers to the internal API format
        final Header[] headers = request.getAllHeaders();
        final Map<String, String> headersInternal = new HashMap<>();
        for (final Header header : headers) {
            // Skip adding the Host header as the signing process will add one.
            if (!header.getName().equalsIgnoreCase(HOST)) {
                headersInternal.put(header.getName(), header.getValue());
            }
        }

        // convert the parameters to the internal API format
        final String queryStr = request.getURI().getRawQuery();
        final Map<String, List<String>> parametersInternal = extractParametersFromQueryString(queryStr);

        // carry over the entity (or an empty entity, if no entity is provided)
        final InputStream content;
        try {

            HttpEntity httpEntity = null;
            if (request instanceof HttpEntityEnclosingRequest) {
                httpEntity = ((HttpEntityEnclosingRequest) request).getEntity();
            }

            // fallback: if we either have an HttpEntityEnclosingRequest without entity or
            //           say a GET request (which does not carry an entity), set the content
            //           to be an empty StringEntity as per the SigV4 spec
            if (httpEntity == null) {
                httpEntity = new StringEntity("");
            }
            content = httpEntity.getContent();

        } catch (final UnsupportedEncodingException e) {

            throw new NeptuneSigV4SignerException("Encoding of the input string failed", e);

        } catch (final IOException e) {

            throw new NeptuneSigV4SignerException("IOException while accessing entity content", e);

        }

        final URI uri = request.getURI();

        // http://example.com:8182 is the endpoint in http://example.com:8182/test/path
        URI endpoint;

        // /test/path is the resource path in http://example.com:8182/test/path
        String resourcePath;

        if (uri.getHost() != null) {
            endpoint = URI.create(uri.getScheme() + "://" + uri.getAuthority());
            resourcePath = uri.getPath();
        } else if (request instanceof HttpRequestWrapper) {
            final String host = ((HttpRequestWrapper) request).getTarget().toURI();
            endpoint = URI.create(host);
            resourcePath = uri.getPath();
        } else {
            throw new NeptuneSigV4SignerException(
                    "Unable to extract host information from the request uri, required for SigV4 signing: " + uri);
        }
        return convertToSignableRequest(
                request.getMethod(),
                endpoint,
                resourcePath,
                headersInternal,
                parametersInternal,
                content);
    }

    @Override
    protected void attachSignature(final HttpUriRequest request, final NeptuneSigV4Signature signature)
            throws NeptuneSigV4SignerException {

        // make sure the request is not null and contains the minimal required set of information
        checkNotNull(signature, "The signature must not be null");
        checkNotNull(signature.getHostHeader(), "The signed Host header must not be null");
        checkNotNull(signature.getXAmzDateHeader(), "The signed X-AMZ-DATE header must not be null");
        checkNotNull(signature.getAuthorizationHeader(), "The signed Authorization header must not be null");


        final Header[] headers = request.getAllHeaders();

        // Check if host header is present in the request headers.
        Optional<String> hostHeaderName = Optional.empty();
        for (final Header header: headers) {
            if (header.getName().equalsIgnoreCase(HOST)) {
                hostHeaderName = Optional.of(header.getName());
            }
        }

        // Remove the host header from the request as we are going to add the host header from the signed request.
        // This also ensures that the right header name is used.
        hostHeaderName.ifPresent(request::removeHeaders);

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

}
