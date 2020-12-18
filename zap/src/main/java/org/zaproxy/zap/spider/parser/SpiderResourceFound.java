/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.spider.parser;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

/**
 * Class SpiderResourceFound is used to store information about found resources by spider parsers.
 *
 * @since 2.11.0
 */
public class SpiderResourceFound {
    /** Original response message. */
    private HttpMessage responseMessage;
    /** Spider depth for resource. */
    private int depth;
    /** HTTP method for resource. */
    private String method;
    /** Uniform resource identifier of resource. */
    private String uri;
    /** Body for the resource. */
    private String body = "";
    /** Defines resource as useful or not useful in the fetching process. */
    private boolean shouldIgnore = false;
    /** Additional request headers to be passed for the resource. */
    private List<HttpHeaderField> requestHeaders = new ArrayList<>();

    /**
     * Instantiates a basic spider resource found as GET.
     *
     * @param responseMessage the response message
     * @param depth the depth of this resource in the crawling process
     * @param uri the universal resource locator
     * @throws NullPointerException if {@code uri} is null.
     */
    public SpiderResourceFound(HttpMessage responseMessage, int depth, String uri) {
        this.responseMessage = responseMessage;
        this.depth = depth;
        this.uri = Objects.requireNonNull(uri);
        this.method = HttpRequestHeader.GET;
    }

    /**
     * Instantiates a basic spider resource found as POST.
     *
     * @param responseMessage the response message
     * @param depth the depth of this resource in the crawling process
     * @param uri the universal resource locator
     * @throws NullPointerException if {@code responseMessage}, {@code uri}, or {@code body} is
     *     null.
     */
    public SpiderResourceFound(HttpMessage responseMessage, int depth, String uri, String body) {
        this(responseMessage, depth, uri);
        this.body = Objects.requireNonNull(body);
        this.method = HttpRequestHeader.POST;
    }

    /**
     * Instantiates a spider resource found as a copy on an existing one.
     *
     * @param resourceFound existing resource found
     * @throws NullPointerException if {@code resourceFound} is null.
     */
    public SpiderResourceFound(SpiderResourceFound resourceFound) {
        this(resourceFound.getResponseMessage(), resourceFound.getDepth(), resourceFound.getUri());
        this.body = resourceFound.getBody();
        this.method = resourceFound.getMethod();
        this.shouldIgnore = resourceFound.isShouldIgnore();
        this.requestHeaders = resourceFound.getRequestHeaders();
    }

    /**
     * Sets whether the resource found should be ignored.
     *
     * @param shouldIgnore boolean value whether to ignore
     */
    public void setShouldIgnore(boolean shouldIgnore) {
        this.shouldIgnore = shouldIgnore;
    }

    /**
     * Adds additional HTTP request headers for the found resource.
     *
     * @param requestHeaders list of headers (null will clear the list)
     */
    public void setRequestHeaders(List<HttpHeaderField> requestHeaders) {
        if (requestHeaders != null) {
            this.requestHeaders = requestHeaders;
        } else {
            this.requestHeaders = new ArrayList<>();
        }
    }

    /**
     * Returns the original response message.
     *
     * @return HTTP message
     */
    public HttpMessage getResponseMessage() {
        return responseMessage;
    }

    /**
     * Returns the spider depth of the resource.
     *
     * @return depth value
     */
    public int getDepth() {
        return depth;
    }

    /**
     * Gives back the method to be applied for the found resource.
     *
     * @return HTTP method
     */
    public String getMethod() {
        return method;
    }

    /**
     * Returns the URI of the found resource.
     *
     * @return uniform resource identifier
     */
    public String getUri() {
        return uri;
    }

    /**
     * Returns request body for the found resource.
     *
     * @return body string (empty if resource is GET-based)
     */
    public String getBody() {
        return body;
    }

    /**
     * States if the found resource should be ignored in the fetching process.
     *
     * @return boolean
     */
    public boolean isShouldIgnore() {
        return shouldIgnore;
    }

    /**
     * Returns additional request headers for the resource found.
     *
     * @return list of HTTP header fields
     */
    public List<HttpHeaderField> getRequestHeaders() {
        return requestHeaders;
    }
}
