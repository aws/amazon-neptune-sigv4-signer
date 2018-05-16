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
 * Exception indicating a problem related to the {@link NeptuneSigV4Signer}
 * implementation or its usage at runtime (e.g., the signing process itself).
 *
 * @author schmdtm
 */
public class NeptuneSigV4SignerException extends Exception {

    /**
     * Constructor.
     *
     * @param msg message explaining the exception cause in detail
     */
    public NeptuneSigV4SignerException(final String msg) {
        super(msg);
    }

    /**
     * Constructor.
     *
     * @param cause the root cause of the exception
     */
    public NeptuneSigV4SignerException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructor.
     *
     * @param msg message explaining the exception cause in detail
     * @param cause the root cause of the exception
     */
    public NeptuneSigV4SignerException(final String msg, final Throwable cause) {
        super(msg, cause);
    }
}
