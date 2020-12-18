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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.withSettings;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Vector;
import net.htmlparser.jericho.Source;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.DatabaseServer;
import org.parosproxy.paros.db.DatabaseUnsupportedException;
import org.parosproxy.paros.db.RecordAlert;
import org.parosproxy.paros.db.RecordHistory;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.db.TableHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.ConnectionParam;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.spider.ExtensionSpider;
import org.zaproxy.zap.spider.Spider;
import org.zaproxy.zap.spider.SpiderController;
import org.zaproxy.zap.spider.SpiderParam;
import org.zaproxy.zap.spider.SpiderTask;
import org.zaproxy.zap.spider.parser.SpiderParserTestUtils.SpiderResource;
import org.zaproxy.zap.spider.parser.SpiderParserTestUtils.TestSpiderParserListener;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link SpiderParserAdditionalHeadersUnitTest}. */
@ExtendWith(MockitoExtension.class)
public class SpiderParserAdditionalHeadersUnitTest extends SpiderParserTestUtils {
    private static final int NUMBER_RESOURCES_TO_SUBMIT = 5;

    /** Sets up the messages in {@link Constant}. */
    @BeforeEach
    public void setUpZap() {
        Constant.getInstance();
        I18N i18n = Mockito.mock(I18N.class, withSettings().lenient());
        given(i18n.getString(anyString())).willReturn("");
        given(i18n.getString(anyString(), any())).willReturn("");
        given(i18n.getLocal()).willReturn(Locale.getDefault());
        Constant.messages = i18n;
    }

    @Test
    public void shouldAddHeadersToFoundUrls() {
        // Given
        List<HttpHeaderField> requestHeaders = new ArrayList<>();
        requestHeaders.add(new HttpHeaderField("Accept", "application/json, text/html, */*"));
        requestHeaders.add(new HttpHeaderField("X-Customer-Header", "xyz"));
        TestSpiderParser testSpiderParser =
                new TestSpiderParser(NUMBER_RESOURCES_TO_SUBMIT, false, requestHeaders);
        TestSpiderParserListener listener = createTestSpiderParserListener();
        testSpiderParser.addSpiderParserListener(listener);
        TestSpiderController testSpiderController = new TestSpiderController(new TestSpider());
        testSpiderParser.addSpiderParserListener(testSpiderController);
        HttpMessage messageResponse = createBasicMessage();
        // When
        testSpiderParser.parseResource(messageResponse, null, 0);
        // Then
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(NUMBER_RESOURCES_TO_SUBMIT)));
        assertThat(
                testSpiderController.getNumberOfSubmittedSpiderTasks(),
                is(equalTo(listener.getNumberOfUrlsFound())));
        listener.getResourcesFound()
                .forEach(
                        r -> {
                            assertThat(r.getHeaders().size(), is(equalTo(requestHeaders.size())));
                        });
    }

    @Test
    public void shouldNotSubmitSameFetchResourcesWithHeaders() {
        // Given
        List<HttpHeaderField> requestHeaders = new ArrayList<>();
        requestHeaders.add(new HttpHeaderField("Accept", "application/json, text/html, */*"));
        requestHeaders.add(new HttpHeaderField("X-Customer-Header", "xyz"));
        TestSpiderParser testSpiderParser =
                new TestSpiderParser(NUMBER_RESOURCES_TO_SUBMIT, false, requestHeaders);
        TestSpiderController testSpiderController = new TestSpiderController(new TestSpider());
        testSpiderParser.addSpiderParserListener(testSpiderController);
        HttpMessage messageResponse = createBasicMessage();
        // When
        testSpiderParser.parseResource(messageResponse, null, 0);
        int numSubmittedSpiderTasksAfterFirstParsing =
                testSpiderController.getNumberOfSubmittedSpiderTasks();
        testSpiderParser.parseResource(messageResponse, null, 0);
        int numSubmittedSpiderTasksAfterSecondParsing =
                testSpiderController.getNumberOfSubmittedSpiderTasks();
        // Then
        testSpiderController
                .getResourcesFound()
                .forEach(
                        r -> {
                            assertThat(r.getRequestBody().isEmpty(), is(equalTo(true)));
                        });
        assertThat(
                numSubmittedSpiderTasksAfterFirstParsing,
                is(equalTo(numSubmittedSpiderTasksAfterSecondParsing)));
    }

    @Test
    public void shouldNotSubmitSamePostResourcesWithHeaders() {
        // Given
        List<HttpHeaderField> requestHeaders = new ArrayList<>();
        requestHeaders.add(new HttpHeaderField("Accept", "application/json, text/html, */*"));
        requestHeaders.add(new HttpHeaderField("X-Customer-Header", "xyz"));
        TestSpiderParser testSpiderParser =
                new TestSpiderParser(NUMBER_RESOURCES_TO_SUBMIT, true, requestHeaders);
        TestSpiderController testSpiderController = new TestSpiderController(new TestSpider());
        testSpiderParser.addSpiderParserListener(testSpiderController);
        HttpMessage messageResponse = createBasicMessage();
        // When
        testSpiderParser.parseResource(messageResponse, null, 0);
        int numSubmittedSpiderTasksAfterFirstParsing =
                testSpiderController.getNumberOfSubmittedSpiderTasks();
        testSpiderParser.parseResource(messageResponse, null, 0);
        int numSubmittedSpiderTasksAfterSecondParsing =
                testSpiderController.getNumberOfSubmittedSpiderTasks();
        // Then
        testSpiderController
                .getResourcesFound()
                .forEach(
                        r -> {
                            assertThat(r.getRequestBody().isEmpty(), is(equalTo(false)));
                        });
        assertThat(
                numSubmittedSpiderTasksAfterFirstParsing,
                is(equalTo(numSubmittedSpiderTasksAfterSecondParsing)));
    }

    @Test
    public void shouldIgnoreHeaderSortOrderAndEmptyHeaders() {
        // Given
        HttpHeaderField headerField1 =
                new HttpHeaderField("Accept", "application/json, text/html, */*");
        HttpHeaderField headerField2 = new HttpHeaderField("X-Customer-Header", "xyz");
        HttpHeaderField headerField3 = new HttpHeaderField("", "");
        List<HttpHeaderField> requestHeadersA = new ArrayList<>();
        requestHeadersA.add(headerField1);
        requestHeadersA.add(headerField2);
        List<HttpHeaderField> requestHeadersB = new ArrayList<>();
        requestHeadersB.add(headerField2);
        requestHeadersB.add(headerField1);
        requestHeadersB.add(headerField3);
        TestSpiderParser testSpiderParser =
                new TestSpiderParser(NUMBER_RESOURCES_TO_SUBMIT, false, new ArrayList<>());
        TestSpiderController testSpiderController = new TestSpiderController(new TestSpider());
        testSpiderParser.addSpiderParserListener(testSpiderController);
        HttpMessage messageResponse = createBasicMessage();
        // When
        testSpiderParser.setRequestHeaders(requestHeadersA);
        testSpiderParser.parseResource(messageResponse, null, 0);
        int numSubmittedSpiderTasksAfterFirstParsing =
                testSpiderController.getNumberOfSubmittedSpiderTasks();
        testSpiderParser.setRequestHeaders(requestHeadersB);
        testSpiderParser.parseResource(messageResponse, null, 0);
        int numSubmittedSpiderTasksAfterSecondParsing =
                testSpiderController.getNumberOfSubmittedSpiderTasks();
        // Then
        assertThat(
                numSubmittedSpiderTasksAfterFirstParsing,
                is(equalTo(numSubmittedSpiderTasksAfterSecondParsing)));
    }

    private static HttpMessage createBasicMessage() {
        HttpMessage message = new HttpMessage();
        try {
            message.setRequestHeader(
                    "GET https://server.com/resource.txt HTTP/1.1\r\nHost: example.com\r\n");
            message.setResponseHeader(
                    "HTTP/1.1 200 OK\r\n"
                            + "Content-Type: text/html; charset=UTF-8\r\n"
                            + "Content-Length: 1");
            message.setResponseBody("a");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return message;
    }

    /** Test spider controller without any default parsers (expecting a test spider). */
    private static class TestSpiderController extends SpiderController {
        private TestSpider spider;
        private final List<SpiderResource> resources = new ArrayList<>();
        private final List<String> urls = new ArrayList<>();

        public TestSpiderController(TestSpider spider) {
            super(spider, new ArrayList<>());
            this.spider = spider;
        }

        @Override
        protected void prepareDefaultParsers() {
            // Do nothing
        }

        @Override
        public void resourceFound(SpiderResourceFound resourceFound) {
            urls.add(resourceFound.getUri());
            resources.add(new SpiderResource(resourceFound));
            super.resourceFound(resourceFound);
        }

        public int getNumberOfUrlsFound() {
            return resources.size();
        }

        public List<String> getUrlsFound() {
            return urls;
        }

        public int getNumberOfResourcesFound() {
            return resources.size();
        }

        public List<SpiderResource> getResourcesFound() {
            return resources;
        }

        public List<SpiderTask> getSubmittedSpiderTasks() {
            return spider.getSubmittedSpiderTasks();
        }

        public int getNumberOfSubmittedSpiderTasks() {
            return spider.getSubmittedSpiderTasks().size();
        }
    }

    /** Test spider with dummy messages and no spider task submission. */
    private static class TestSpider extends Spider {
        private static final ResourceBundle DUMMY_RESOURCE_BUNDLE;
        private static final ExtensionSpider DUMMY_SPIDER_EXTENSION;
        private List<SpiderTask> submittedSpiderTasks = new ArrayList<>();

        static {
            DUMMY_RESOURCE_BUNDLE =
                    new ResourceBundle() {
                        @Override
                        protected Object handleGetObject(String key) {
                            return "";
                        }

                        @Override
                        public Enumeration<String> getKeys() {
                            return Collections.emptyEnumeration();
                        }
                    };
            DUMMY_SPIDER_EXTENSION = new ExtensionSpider();
            DUMMY_SPIDER_EXTENSION.setMessages(DUMMY_RESOURCE_BUNDLE);
            HistoryReference.setTableHistory(new TestTableHistory());
            HistoryReference.setTableAlert(new TestTableAlert());
        }

        public TestSpider() {
            super(
                    "test",
                    DUMMY_SPIDER_EXTENSION,
                    new SpiderParam(),
                    new ConnectionParam(),
                    Model.getSingleton(),
                    null);
        }

        @Override
        protected synchronized void submitTask(SpiderTask task) {
            submittedSpiderTasks.add(task);
        }

        public List<SpiderTask> getSubmittedSpiderTasks() {
            return submittedSpiderTasks;
        }
    }

    /** Test table for history doing nothing. */
    private static class TestTableHistory implements TableHistory {

        @Override
        public void databaseOpen(DatabaseServer dbServer)
                throws DatabaseException, DatabaseUnsupportedException {
            // Do nothing
        }

        @Override
        public RecordHistory write(long sessionId, int histType, HttpMessage msg)
                throws HttpMalformedHeaderException, DatabaseException {
            return new RecordHistory();
        }

        @Override
        public void updateNote(int historyId, String note) throws DatabaseException {
            // Do nothing
        }

        @Override
        public RecordHistory read(int historyId)
                throws HttpMalformedHeaderException, DatabaseException {
            return new RecordHistory();
        }

        @Override
        public int lastIndex() {
            return 0;
        }

        @Override
        public List<Integer> getHistoryList(
                long sessionId, int histType, String filter, boolean isRequest)
                throws DatabaseException {
            return new ArrayList<>();
        }

        @Override
        public List<Integer> getHistoryIdsStartingAt(long sessionId, int startAtHistoryId)
                throws DatabaseException {
            return new ArrayList<>();
        }

        @Override
        public List<Integer> getHistoryIdsOfHistTypeStartingAt(
                long sessionId, int startAtHistoryId, int... histTypes) throws DatabaseException {
            return new ArrayList<>();
        }

        @Override
        public List<Integer> getHistoryIdsOfHistType(long sessionId, int... histTypes)
                throws DatabaseException {
            return new ArrayList<>();
        }

        @Override
        public List<Integer> getHistoryIdsExceptOfHistTypeStartingAt(
                long sessionId, int startAtHistoryId, int... histTypes) throws DatabaseException {
            return new ArrayList<>();
        }

        @Override
        public List<Integer> getHistoryIdsExceptOfHistType(long sessionId, int... histTypes)
                throws DatabaseException {
            return new ArrayList<>();
        }

        @Override
        public List<Integer> getHistoryIds(long sessionId) throws DatabaseException {
            return new ArrayList<>();
        }

        @Override
        public RecordHistory getHistoryCache(HistoryReference ref, HttpMessage reqMsg)
                throws DatabaseException, HttpMalformedHeaderException {
            return new RecordHistory();
        }

        @Override
        public void deleteTemporary() throws DatabaseException {
            // Do nothing
        }

        @Override
        public void deleteHistoryType(long sessionId, int historyType) throws DatabaseException {
            // Do nothing
        }

        @Override
        public void deleteHistorySession(long sessionId) throws DatabaseException {
            // Do nothing
        }

        @Override
        public void delete(List<Integer> ids, int batchSize) throws DatabaseException {
            // Do nothing
        }

        @Override
        public void delete(List<Integer> ids) throws DatabaseException {
            // Do nothing
        }

        @Override
        public void delete(int historyId) throws DatabaseException {
            // Do nothing
        }

        @Override
        public boolean containsURI(
                long sessionId, int historyType, String method, String uri, byte[] body)
                throws DatabaseException {
            return false;
        }
    }

    /** Test table for alerts doing nothing. */
    private static class TestTableAlert implements TableAlert {

        @Override
        public void databaseOpen(DatabaseServer dbServer)
                throws DatabaseException, DatabaseUnsupportedException {
            // Do nothing
        }

        @Override
        public RecordAlert read(int alertId) throws DatabaseException {
            return new RecordAlert();
        }

        @Override
        public RecordAlert write(
                int scanId,
                int pluginId,
                String alert,
                int risk,
                int confidence,
                String description,
                String uri,
                String param,
                String attack,
                String otherInfo,
                String solution,
                String reference,
                String evidence,
                int cweId,
                int wascId,
                int historyId,
                int sourceHistoryId,
                int sourceId,
                String alertRef)
                throws DatabaseException {
            return new RecordAlert();
        }

        @Override
        public Vector<Integer> getAlertListBySession(long sessionId) throws DatabaseException {
            return new Vector<>();
        }

        @Override
        public void deleteAlert(int alertId) throws DatabaseException {
            // Do nothing
        }

        @Override
        public int deleteAllAlerts() throws DatabaseException {
            return 0;
        }

        @Override
        public void update(
                int alertId,
                String alert,
                int risk,
                int confidence,
                String description,
                String uri,
                String param,
                String attack,
                String otherInfo,
                String solution,
                String reference,
                String evidence,
                int cweId,
                int wascId,
                int sourceHistoryId)
                throws DatabaseException {
            // Do nothing
        }

        @Override
        public void updateHistoryIds(int alertId, int historyId, int sourceHistoryId)
                throws DatabaseException {
            // Do nothing
        }

        @Override
        public List<RecordAlert> getAlertsBySourceHistoryId(int historyId)
                throws DatabaseException {
            return new ArrayList<>();
        }

        @Override
        public Vector<Integer> getAlertList() throws DatabaseException {
            return new Vector<>();
        }
    }

    /**
     * Test spider parser parses all resources and submits a fixed number of resources found with a
     * given path prefix and suffix either as GET or POST with a body.
     */
    private static class TestSpiderParser extends SpiderParser {
        private int numResourcesToSubmit;
        private boolean postWithBody;
        private List<HttpHeaderField> requestHeaders = null;
        private String resourcePathPrefix = "";
        private String resourcePathSuffix = "";
        private String bodyPrefix = "";

        public TestSpiderParser(
                int numResourcesToSubmit,
                boolean postWithBody,
                List<HttpHeaderField> requestHeaders) {
            this.numResourcesToSubmit = numResourcesToSubmit;
            if (this.numResourcesToSubmit < 1) {
                this.numResourcesToSubmit = 1;
            }
            this.postWithBody = postWithBody;
            this.requestHeaders = requestHeaders;
        }

        @Override
        public boolean parseResource(HttpMessage message, Source source, int depth) {
            for (int i = 0; i < numResourcesToSubmit; ++i) {
                if (postWithBody) {
                    notifyListenersPostResourceFound(
                            message, depth, buildResourceUrl(i), buildBody(i), requestHeaders);
                } else {
                    processURL(
                            message,
                            depth,
                            buildResourceUrl(i),
                            message.getRequestHeader().getURI().getProtocolCharset(),
                            requestHeaders);
                }
            }
            return true;
        }

        @Override
        public boolean canParseResource(
                HttpMessage message, String path, boolean wasAlreadyConsumed) {
            return true;
        }

        private String buildResourceUrl(int i) {
            StringBuilder urlBuilder = new StringBuilder(20);
            urlBuilder.append("https://server.com/");
            if (resourcePathPrefix != null && !resourcePathPrefix.isEmpty()) {
                urlBuilder.append(resourcePathPrefix);
            }
            urlBuilder.append(i);
            if (resourcePathSuffix != null && !resourcePathSuffix.isEmpty()) {
                urlBuilder.append(resourcePathSuffix);
            }
            return urlBuilder.toString();
        }

        private String buildBody(int i) {
            StringBuilder bodyBuilder = new StringBuilder(20);
            if (bodyPrefix != null && !bodyPrefix.isEmpty()) {
                bodyBuilder.append(bodyPrefix);
            }
            bodyBuilder.append("\n>>" + i);
            return bodyBuilder.toString();
        }

        public void setResourcePathPrefix(String resourcePathPrefix) {
            this.resourcePathPrefix = resourcePathPrefix;
        }

        public void setResourcePathSuffix(String resourcePathSuffix) {
            this.resourcePathSuffix = resourcePathSuffix;
        }

        public void setBodyPrefix(String bodyPrefix) {
            this.bodyPrefix = bodyPrefix;
        }

        public void setRequestHeaders(List<HttpHeaderField> requestHeaders) {
            this.requestHeaders = requestHeaders;
        }
    }
}
