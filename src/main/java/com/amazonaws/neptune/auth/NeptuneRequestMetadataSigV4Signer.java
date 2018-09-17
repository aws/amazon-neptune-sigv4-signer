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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.amazonaws.auth.internal.SignerConstants.AUTHORIZATION;
import static com.amazonaws.auth.internal.SignerConstants.HOST;
import static com.amazonaws.auth.internal.SignerConstants.X_AMZ_DATE;
import static com.amazonaws.auth.internal.SignerConstants.X_AMZ_SECURITY_TOKEN;

/**
 * Signer for HTTP requests encapsulalted in {@link RequestMetadata}s.
 * <p>
 * Note that there are certain limitations for the usage of this class. In particular:
 * <ul>
 *     <li> The implementation adds a "Host" header. This may lead to problems if the original request has a host header
 *          with a name in different capitalization (e.g. "host"), leading to duplicate host headers and the signing process
 *          to fail. Hence, when using the API you need to make sure that there is either no host header in your original
 *          request or the host header uses the exact string "Host" as the header name.</li>
 *     <li> When using GET, the underlying HTTP request needs to encode whitespaces in query parameters using '%20'
 *          rather than (what most APIs such as the Apache commons {@link org.apache.http.client.utils.URIBuilder} do)
 *          using '+'.</li>
 * </ul>
 */
public class NeptuneRequestMetadataSigV4Signer extends NeptuneSigV4SignerBase<RequestMetadata> {
    /**
     * Create a V4 Signer for {@link RequestMetadata}.
     *
     * @param regionName             name of the region for which the request is signed
     * @param awsCredentialsProvider the provider offering access to the credentials used for signing the request
     * @throws NeptuneSigV4SignerException in case initialization fails
     */
    public NeptuneRequestMetadataSigV4Signer(
            final String regionName, final AWSCredentialsProvider awsCredentialsProvider)
            throws NeptuneSigV4SignerException {

        super(regionName, awsCredentialsProvider);
    }

    /**
     * Converts a {@link RequestMetadata} to a signable metadata by adding signature headers for AWS SigV4 auth.
     *
     * @param request the request metadata object.
     * @return the signed {@link RequestMetadata}.
     * @throws NeptuneSigV4SignerException if there are issues while attempting to generate the signature.
     */
    @Override
    protected SignableRequest<?> toSignableRequest(final RequestMetadata request)
            throws NeptuneSigV4SignerException {

        // make sure the request is not null and contains the minimal required set of information
        checkNotNull(request, "The request must not be null");
        checkNotNull(request.getFullUri(), "The request URI must not be null");
        checkNotNull(request.getMethod(), "The request method must not be null");

        final URI fullUri = URI.create(request.getFullUri());
        checkNotNull(fullUri.getAuthority(), "Authority must not be null");
        checkNotNull(fullUri.getScheme(), "Scheme must not be null");

        // convert the headers to the internal API format
        final Map<String, String> headersInternal = request.getHeaders()
                .entrySet()
                .stream()
                .filter(e -> !e.getKey().equalsIgnoreCase(HOST))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        // convert the parameters to the internal API format
        final String queryStr = fullUri.getRawQuery();
        final Map<String, List<String>> parametersInternal = extractParametersFromQueryString(queryStr);

        // carry over the entity (or an empty entity, if no entity is provided)
        final InputStream content;

        final byte[] bytes;
        if (request.getContent().isPresent()) {
            bytes = request.getContent().get();
        } else {
            bytes = "".getBytes(StandardCharsets.UTF_8);
        }
        content = new ByteArrayInputStream(bytes);

        final URI endpointUri = URI.create(fullUri.getScheme() + "://" + fullUri.getAuthority());
        final String resourcePath = fullUri.getPath();
        return convertToSignableRequest(
                request.getMethod(),
                endpointUri,
                resourcePath,
                headersInternal,
                parametersInternal,
                content);
    }

    /**
     * Takes a {@link RequestMetadata} and updates the headers required for SigV4 auth. These include the host header,
     * date header and the authorization header obtained from the {@link NeptuneSigV4Signature}.
     * Removes the host header if already present in the request.
     * @param request   the request metadata.
     * @param signature the signature information to attach
     * @throws NeptuneSigV4SignerException if there is an error in performing the update.
     */
    @Override
    protected void attachSignature(final RequestMetadata request, final NeptuneSigV4Signature signature)
            throws NeptuneSigV4SignerException {

        // make sure the request is not null and contains the minimal required set of information
        checkNotNull(signature, "The signature must not be null");
        checkNotNull(signature.getHostHeader(), "The signed Host header must not be null");
        checkNotNull(signature.getXAmzDateHeader(), "The signed X-AMZ-DATE header must not be null");
        checkNotNull(signature.getAuthorizationHeader(), "The signed Authorization header must not be null");

        final Map<String, String> headers = request.getHeaders();
        // Check if host header is present in the request headers.
        Optional<String> hostHeaderName = Optional.empty();
        for (String name: headers.keySet()) {
            if (name.equalsIgnoreCase(HOST)) {
                hostHeaderName = Optional.of(name);
                break;
            }
        }

        // Remove the host header from the request as we are going to add the host header from the signed request.
        // This also ensures that the right header name is used.
        hostHeaderName.ifPresent(name -> headers.remove(name));

        request.getHeaders().put(HOST, signature.getHostHeader());
        request.getHeaders().put(X_AMZ_DATE, signature.getXAmzDateHeader());
        request.getHeaders().put(AUTHORIZATION, signature.getAuthorizationHeader());

        // https://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html
        // For temporary security credentials, it requires an additional HTTP header
        // or query string parameter for the security token. The name of the header
        // or query string parameter is X-Amz-Security-Token, and the value is the session token.
        if (!signature.getSessionToken().isEmpty()) {
            request.getHeaders().put(X_AMZ_SECURITY_TOKEN, signature.getSessionToken());
        }
    }

}
