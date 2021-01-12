/*
 * MIT License
 *
 * Copyright (c) 2018 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

package ee.ria.taraauthserver.config.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotNull;

@Data
@Validated
@ConfigurationProperties(prefix = "tara.legal-person-authentication")
public class LegalPersonProperties {

    private boolean enabled = true;

    @NotNull
    private String xRoadServerUrl;

    private int xRoadServerConnectTimeoutInMilliseconds = 3000;

    private int xRoadServerReadTimeoutInMilliseconds = 3000;

    @NotNull
    private String xRoadServiceInstance;

    @NotNull
    private String xRoadServiceMemberClass;

    @NotNull
    private String xRoadServiceMemberCode;

    @NotNull
    private String xRoadServiceSubsystemCode;

    @NotNull
    private String xRoadClientSubsystemInstance;

    @NotNull
    private String xRoadClientSubsystemMemberClass;

    @NotNull
    private String xRoadClientSubsystemMemberCode;

    @NotNull
    private String xRoadClientSubsystemCode;

    private String[] esindusv2AllowedTypes = new String[]{"TÜ", "UÜ", "OÜ", "AS", "TÜH", "SA", "MTÜ"};
}
