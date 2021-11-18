// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package start_test

import (
	"fmt"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger/enums"
	"github.com/ZupIT/horusec/internal/enums/outputtype"
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
	"os"
	"path/filepath"

	"github.com/ZupIT/horusec/internal/utils/testutil"
)

var _ = Describe("running binary Horusec with start parameter", func() {
	var (
		session     *gexec.Session
		flags       map[string]string
		projectPath = testutil.GoExample2
	)

	JustBeforeEach(func() {
		var err error
		flags[testutil.StartFlagDisableDocker] = "true"
		cmd := testutil.GinkgoGetHorusecCmdWithFlags(testutil.CmdStart, flags)
		session, err = gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
		Expect(err).NotTo(HaveOccurred())
		session.Wait(testutil.AverageTimeoutAnalyzeForExamplesFolder)

		if _, hasReturnErrorFlag := flags[testutil.StartFlagReturnError]; hasReturnErrorFlag {
			Expect(session).Should(gexec.Exit(1))
		} else {
			Expect(session).Should(gexec.Exit(0))
		}
	})

	When("global flag --log-level is passed", func() {
		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath: projectPath,
				testutil.GlobalFlagLogLevel:   enums.TraceLevel.String(),
			}
		})

		It("Checks if the log level was set as trace", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(`\"log_level\": \"trace\"`))
		})
	})

	When("global flag --config-file-path is passed", func() {
		configFilePathToTest := filepath.Join(projectPath, "horusec-config.json")

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:     projectPath,
				testutil.GlobalFlagConfigFilePath: configFilePathToTest,
				testutil.GlobalFlagLogLevel:       enums.TraceLevel.String(),
			}
		})

		It("Checks if the config file path was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"config_file_path\": \"%s\"`, testutil.NormalizePathToAssertInJSON(configFilePathToTest))))
		})
	})

	When("global flag --log-file-path is passed", func() {
		var logFilePathToTest = filepath.Join(os.TempDir(), fmt.Sprintf("%s-test.txt", uuid.New()))

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:  projectPath,
				testutil.GlobalFlagLogFilePath: logFilePathToTest,
			}
		})

		It("Checks if the log file path was set and file is created", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`Set log file to %s`, testutil.NormalizePathToAssert(logFilePathToTest))))
			Expect(logFilePathToTest).Should(BeAnExistingFile())
		})
	})

	When("--disable-docker is passed", func() {
		It("Checks if the disable docker was set as true", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(`\"disable_docker\": true`))
		})
	})

	When("--project-path is passed", func() {
		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath: projectPath,
			}
		})

		It("Checks if the project path was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(testutil.NormalizePathToAssert(testutil.GoExample2)))
		})
	})

	When("--analysis-timeout is passed", func() {
		analysisTimeout := "500"

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:     projectPath,
				testutil.StartFlagAnalysisTimeout: analysisTimeout,
			}
		})

		It("Checks if the timeout property was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf("Horusec will return a timeout after %s seconds.", analysisTimeout)))
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"timeout_in_seconds_analysis\": %s`, analysisTimeout)))
		})
	})

	When("--authorization is passed", func() {
		repoAuthorization := uuid.New().String()

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:   projectPath,
				testutil.StartFlagAuthorization: repoAuthorization,
			}
		})

		It("Checks if the repository authorization property was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"repository_authorization\": \"%s\"`, testutil.NormalizePathToAssertInJSON(repoAuthorization))))
		})
	})

	When("--certificate-path is passed", func() {
		var certificateFileWithPath string

		BeforeEach(func() {
			file, err := os.CreateTemp(os.TempDir(), "*.crt")
			if err != nil {
				Fail(fmt.Sprintf("error: %v", err))
			}
			certificateFileWithPath = file.Name()

			flags = map[string]string{
				testutil.StartFlagProjectPath:     projectPath,
				testutil.StartFlagCertificatePath: certificateFileWithPath,
			}
		})

		It("Checks if the cert path property was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"cert_path\": \"%s\"`, testutil.NormalizePathToAssertInJSON(certificateFileWithPath))))
		})
	})

	When("--output-format and --json-output-file is passed as JSON", func() {
		jsonOutputPath := filepath.Join(os.TempDir(), fmt.Sprintf("%s-e2e-output.json", uuid.New()))

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:        projectPath,
				testutil.StartFlagOutputFormat:       outputtype.JSON,
				testutil.StartFlagJSONOutputFilePath: jsonOutputPath,
			}
		})

		It("Checks if format was set as JSON and the file is created", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"print_output_type\": \"%s\"`, outputtype.JSON)))
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"json_output_file_path\": \"%s\"`, testutil.NormalizePathToAssertInJSON(jsonOutputPath))))
			Expect(jsonOutputPath).Should(BeAnExistingFile())
		})
	})

	When("--output-format and --json-output-file is passed as Text", func() {
		textOutputPath := filepath.Join(os.TempDir(), fmt.Sprintf("%s-e2e-output.txt", uuid.New()))

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:        projectPath,
				testutil.StartFlagOutputFormat:       outputtype.Text,
				testutil.StartFlagJSONOutputFilePath: textOutputPath,
			}
		})

		It("Checks if format was set as text and the file is created", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"print_output_type\": \"%s\"`, outputtype.Text)))
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"json_output_file_path\": \"%s\"`, testutil.NormalizePathToAssertInJSON(textOutputPath))))
			Expect(textOutputPath).Should(BeAnExistingFile())
		})
	})

	When("--output-format is passed as sonarqube with --json-output-file as JSON", func() {
		sonarqubeOutputPath := filepath.Join(os.TempDir(), fmt.Sprintf("%s-e2e-output-sonarqube.json", uuid.New()))

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:        projectPath,
				testutil.StartFlagOutputFormat:       outputtype.SonarQube,
				testutil.StartFlagJSONOutputFilePath: sonarqubeOutputPath,
			}
		})

		It("Checks if format was set as sonarqube and the JSON file is created", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"print_output_type\": \"%s\"`, outputtype.SonarQube)))
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"json_output_file_path\": \"%s\"`, testutil.NormalizePathToAssertInJSON(sonarqubeOutputPath))))
			Expect(sonarqubeOutputPath).Should(BeAnExistingFile())
		})
	})

	When("--request-timeout is passed", func() {
		requestTimeout := "500"

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:    projectPath,
				testutil.StartFlagRequestTimeout: requestTimeout,
			}
		})

		It("Checks if the request timeout property was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"timeout_in_seconds_request\": %s`, requestTimeout)))
		})
	})

	When("--return-error is passed", func() {
		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:   projectPath,
				testutil.StartFlagReturnError:   "true",
			}
		})

		It("Checks if the return error property was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(`"return_error_if_found_vulnerability\": true`))
			Expect(session.ExitCode()).Should(Equal(1))
		})
	})

	When("--risk-accepted is passed", func() {
		riskAcceptedHash := "8d75739ff88edd7acd60321ae6c7ea9f211048f6fdedb426eb58556ad4d87ea4"

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:   testutil.JavaScriptExample4,
				testutil.StartFlagRiskAccept:    riskAcceptedHash,
				testutil.StartFlagDisableDocker: "true",
			}
		})

		It("Checks if the risk accepted property was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`"risk_accept_hashes\": [\n    \"%s\"\n  ]`, riskAcceptedHash)))
			Expect(session.Out.Contents()).To(ContainSubstring("YOUR ANALYSIS HAD FINISHED WITHOUT ANY VULNERABILITY!"))
		})
	})

	When("--false-positive is passed", func() {
		falsePositiveHash := "8d75739ff88edd7acd60321ae6c7ea9f211048f6fdedb426eb58556ad4d87ea4"

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:   testutil.JavaScriptExample4,
				testutil.StartFlagFalsePositive: falsePositiveHash,
				testutil.StartFlagDisableDocker: "true",
			}
		})

		It("Checks if the risk accepted property was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`"false_positive_hashes\": [\n    \"%s\"\n  ]`, falsePositiveHash)))
			Expect(session.Out.Contents()).To(ContainSubstring("YOUR ANALYSIS HAD FINISHED WITHOUT ANY VULNERABILITY!"))
		})
	})

	When("--repository-name is passed", func() {
		repositoryName := "horusec-e2e-test"

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:   projectPath,
				testutil.StartFlagRepositoryName: repositoryName,
			}
		})

		It("Checks if the repository name property was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"repository_name\": \"%s\"`, repositoryName)))
		})
	})
})
