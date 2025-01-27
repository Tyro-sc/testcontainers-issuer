/*
 * Copyright © 2025 altus34 (altus34@gmail.com)
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
package sc.tyro.testcontainers.issuer;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

import static org.testcontainers.utility.MountableFile.forClasspathResource;

public class IssuerContainer extends GenericContainer<IssuerContainer> {

    private static final DockerImageName DEFAULT_IMAGE_NAME = DockerImageName.parse("nginx");

    private static final int HTTP_PORT = 80;
    private static final int HTTPS_PORT = 443;
    private static final String DEFAULT_TAG = "1.27-alpine";
    private final String name;
    private final boolean secured;

    public static IssuerContainer withDefaults() {
        return new IssuerContainer("default", DEFAULT_IMAGE_NAME.withTag(DEFAULT_TAG), false);
    }

    public static IssuerContainer securedDefaults() {
        return new IssuerContainer("default", DEFAULT_IMAGE_NAME.withTag(DEFAULT_TAG), true);
    }

    public IssuerContainer(String custom, boolean secured) {
        this(custom, DEFAULT_IMAGE_NAME.withTag(DEFAULT_TAG), secured);
    }

    public IssuerContainer(String name, DockerImageName dockerImageName, boolean secured) {
        super(dockerImageName);
        this.name = name;
        this.secured = secured;
        dockerImageName.assertCompatibleWith(DEFAULT_IMAGE_NAME);
        addExposedPort(HTTP_PORT);
        addExposedPort(HTTPS_PORT);
    }

    @Override
    public void start() {
        super.start();
        var jwksUri = "http://" + getHost() + ":" + getMappedPort(HTTP_PORT) + "/" + name;

        if (secured)
            jwksUri = "https://" + getHost() + ":" + getMappedPort(HTTPS_PORT) + "/" + name;

        try {
            execInContainer("sh", "-c", "export jwks_uri=" + jwksUri + " && /docker-entrypoint.d/start.sh");

        } catch (Exception e) {
            throw new RuntimeException("Failed to execute container entrypoint", e);
        }
    }

    @Override
    protected void configure() {
        super.configure();
        withCopyFileToContainer(forClasspathResource("/nginx/public"), "/usr/share/nginx/html");
        withCopyFileToContainer(forClasspathResource("/nginx/tls"), "/usr/share/ca-certificates/mkcert");
        withCopyFileToContainer(forClasspathResource("/nginx/conf"), "/etc/nginx/conf.d");
        withCopyFileToContainer(forClasspathResource("/nginx/start.sh", 744), "/docker-entrypoint.d/start.sh");
    }

    public String name() {
        return name;
    }

    public String url() {
        if (secured) {
            return "https://" + getHost() + ":" + getMappedPort(443) + "/" + name;
        } else {
            return "http://" + getHost() + ":" + getMappedPort(80) + "/" + name;
        }
    }

    public TokenForgery forgery() {
        return new TokenForgery(url());
    }
}
