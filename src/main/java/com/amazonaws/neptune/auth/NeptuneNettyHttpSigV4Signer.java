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
import com.amazonaws.util.StringUtils;
import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpHeaders;
import org.apache.http.entity.StringEntity;

import java.io.ByteArrayInputStream;
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

/**
 * Signer for HTTP requests made via Netty clients {@link FullHttpRequest}s.
 */
public class NeptuneNettyHttpSigV4Signer extends NeptuneSigV4SignerBase<FullHttpRequest> {

    /**
     * Create a V4 Signer for Netty HTTP requests.
     *
     * @param regionName             name of the region for which the request is signed
     * @param awsCredentialsProvider the provider offering access to the credentials used for signing the request
     * @throws NeptuneSigV4SignerException in case initialization fails
     */
    public NeptuneNettyHttpSigV4Signer(
            final String regionName, final AWSCredentialsProvider awsCredentialsProvider)
            throws NeptuneSigV4SignerException {

        super(regionName, awsCredentialsProvider);
    }

    @Override
    protected SignableRequest<?> toSignableRequest(final FullHttpRequest request)
            throws NeptuneSigV4SignerException {

        // make sure the request is not null and contains the minimal required set of information
        checkNotNull(request, "The request must not be null");
        checkNotNull(request.uri(), "The request URI must not be null");
        checkNotNull(request.method(), "The request method must not be null");

        // convert the headers to the internal API format
        final HttpHeaders headers = request.headers();
        final Map<String, String> headersInternal = new HashMap<>();

        String hostName = "";

        // we don't want to add the Host header as the Signer always adds the host header.
        for (String header : headers.names()) {
            // Skip adding the Host header as the signing process will add one.
            if (!header.equalsIgnoreCase(HOST)) {
                headersInternal.put(header, headers.get(header));
            } else {
                hostName = headers.get(header);
            }
        }

        // convert the parameters to the internal API format
        final URI uri = URI.create(request.uri());

        final String queryStr = uri.getQuery();
        final Map<String, List<String>> parametersInternal = new HashMap<>(extractParametersFromQueryString(queryStr));

        // carry over the entity (or an empty entity, if no entity is provided)
        final InputStream content;
        final ByteBuf contentBuffer = request.content();
        boolean hasContent = false;
        try {
            if (contentBuffer != null && contentBuffer.isReadable()) {
                hasContent = true;
                contentBuffer.retain();
                byte[] bytes = new byte[contentBuffer.readableBytes()];
                contentBuffer.getBytes(contentBuffer.readerIndex(), bytes);
                content = new ByteArrayInputStream(bytes);
            } else {
                content = new StringEntity("").getContent();
            }
        } catch (UnsupportedEncodingException e) {
            throw new NeptuneSigV4SignerException("Encoding of the input string failed", e);
        } catch (IOException e) {
            throw new NeptuneSigV4SignerException("IOException while accessing entity content", e);
        } finally {
            if (hasContent) {
                contentBuffer.release();
            }
        }

        if (StringUtils.isNullOrEmpty(hostName)) {
            // try to extract hostname from the uri since hostname was not provided in the header.
            final String authority = uri.getAuthority();
            if (authority == null) {
                throw new NeptuneSigV4SignerException("Unable to identify host information,"
                        + " either hostname should be provided in the uri or should be passed as a header");
            }

            hostName = authority;
        }

        // Gremlin websocket requests don't contain protocol information. Here, http:// doesn't have any consequence
        // other than letting the signer work with a full valid uri. The protocol is not used anywhere in signing.
        final URI endpointUri = URI.create("http://" + hostName);

        return convertToSignableRequest(
                request.method().name(),
                endpointUri,
                uri.getPath(),
                headersInternal,
                parametersInternal,
                content);
    }

    @Override
    protected void attachSignature(final FullHttpRequest request, final NeptuneSigV4Signature signature)
            throws NeptuneSigV4SignerException {

        // make sure the request is not null and contains the minimal required set of information
        checkNotNull(signature, "The signature must not be null");
        checkNotNull(signature.getHostHeader(), "The signed Host header must not be null");
        checkNotNull(signature.getXAmzDateHeader(), "The signed X-AMZ-DATE header must not be null");
        checkNotNull(signature.getAuthorizationHeader(), "The signed Authorization header must not be null");

        final HttpHeaders headers = request.headers();
        Optional<String> hostHeaderName = Optional.empty();
        // Check if host header is present in the request headers.
        for (String name: headers.names()) {
            if (name.equalsIgnoreCase(HOST)) {
                hostHeaderName = Optional.of(name);
                break;
            }
        }

        // Remove the host header from the request as we are going to add the host header from the signed request.
        // This also ensures that the right header name is used.
        hostHeaderName.ifPresent(name -> headers.remove(name));
        request.headers().add(HOST, signature.getHostHeader());
        request.headers().add(X_AMZ_DATE, signature.getXAmzDateHeader());
        request.headers().add(AUTHORIZATION, signature.getAuthorizationHeader());
    }
}
