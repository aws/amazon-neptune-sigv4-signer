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

/**
 * Interface to hook in Signature V4 signing logics as per
 * https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html.
 *
 * T is the type of the request to be signed, which allows us to support
 * implementation for different HTTP client APIs.
 *
 * @param <T> type of the request to be signed
 * @author schmdtm
 */
public interface NeptuneSigV4Signer<T> {

    /**
     * Sign the given input request using SigV4.
     *
     * @param request the request to be signed
     * @throws NeptuneSigV4SignerException in case something goes wrong
     */
     void signRequest(final T request) throws NeptuneSigV4SignerException;

}
