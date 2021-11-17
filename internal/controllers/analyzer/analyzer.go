// Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

package analyzer

import (
	"fmt"
	"io"
	"path/filepath"

	"log"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	enumsAnalysis "github.com/ZupIT/horusec-devkit/pkg/enums/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	enumsVulnerability "github.com/ZupIT/horusec-devkit/pkg/enums/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"

	"github.com/ZupIT/horusec/config"
	languagedetect "github.com/ZupIT/horusec/internal/controllers/language_detect"
	"github.com/ZupIT/horusec/internal/controllers/printresults"
	"github.com/ZupIT/horusec/internal/engine"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	horusecAPI "github.com/ZupIT/horusec/internal/services/horusec_api"
)

const LoadingDelay = 200 * time.Millisecond

// LanguageDetect is the interface that detect all languages in some directory.
type LanguageDetect interface {
	Detect(directory string) ([]languages.Language, error)
}

// PrintResults is the interface tha print the results to stdout
//
// Print print the results to stdout and return the total vulnerabilities that was printed.
type PrintResults interface {
	Print() (int, error)
	SetAnalysis(analysis *analysis.Analysis)
}

// HorusecService is the interface that interacts with Horusec API
type HorusecService interface {
	SendAnalysis(*analysis.Analysis) error
	GetAnalysis(uuid.UUID) (*analysis.Analysis, error)
}

type Analyzer struct {
	analysis        *analysis.Analysis
	config          *config.Config
	languageDetect  LanguageDetect
	printController PrintResults
	horusec         HorusecService
	loading         *spinner.Spinner
	engine          *engine.Engine
}

//nolint:funlen
func NewAnalyzer(cfg *config.Config) *Analyzer {
	entity := &analysis.Analysis{
		ID:        uuid.New(),
		CreatedAt: time.Now(),
		Status:    enumsAnalysis.Running,
	}
	return &Analyzer{
		analysis:        entity,
		config:          cfg,
		languageDetect:  languagedetect.NewLanguageDetect(cfg, entity.ID),
		printController: printresults.NewPrintResults(entity, cfg),
		horusec:         horusecAPI.NewHorusecAPIService(cfg),
		loading:         newScanLoading(cfg),
		engine:          engine.New(cfg, entity),
	}
}

func (a *Analyzer) Analyze() (totalVulns int, err error) {
	a.removeTrashByInterruptProcess()
	totalVulns, err = a.runAnalysis()
	a.removeHorusecFolder()
	return totalVulns, err
}

func (a *Analyzer) removeTrashByInterruptProcess() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			a.removeHorusecFolder()
			log.Fatal()
		}
	}()
}

func (a *Analyzer) removeHorusecFolder() {
	err := os.RemoveAll(filepath.Join(a.config.ProjectPath, ".horusec"))
	logger.LogErrorWithLevel(messages.MsgErrorRemoveAnalysisFolder, err)
}

func (a *Analyzer) runAnalysis() (totalVulns int, err error) {
	langs, err := a.languageDetect.Detect(a.config.ProjectPath)
	if err != nil {
		return 0, err
	}

	if a.config.EnableGitHistoryAnalysis {
		logger.LogWarnWithLevel(messages.MsgWarnGitHistoryEnable)
		fmt.Println()
	}

	if err := a.engine.Run(langs); err != nil {
		panic(fmt.Sprintf("------PANIC!!!!------\n%v", err))
	}
	if err = a.sendAnalysis(); err != nil {
		logger.LogStringAsError(fmt.Sprintf("[HORUSEC] %s", err.Error()))
	}
	return a.startPrintResults()
}
func (a *Analyzer) startPrintResults() (int, error) {
	a.formatAnalysisToPrint()
	a.printController.SetAnalysis(a.analysis)
	return a.printController.Print()
}

func (a *Analyzer) sendAnalysis() error {
	a.formatAnalysisToSendToAPI()
	if err := a.horusec.SendAnalysis(a.analysis); err != nil {
		return err
	}
	analysisSaved, err := a.horusec.GetAnalysis(a.analysis.ID)
	if err != nil {
		return err
	}
	if analysisSaved != nil && analysisSaved.ID != uuid.Nil {
		a.analysis = analysisSaved
	}
	return err
}

func (a *Analyzer) formatAnalysisToPrint() {
	a.analysis = a.setFalsePositive()
	if !a.config.EnableInformationSeverity {
		a.analysis = a.removeInfoVulnerabilities()
	}
	a.analysis = a.removeVulnerabilitiesByTypes()
	a.analysis = a.removeVulnerabilitiesBySeverity()
}

func (a *Analyzer) formatAnalysisToSendToAPI() {
	a.analysis = a.setAnalysisFinishedData()
	a.analysis = a.setupIDInAnalysisContents()
	a.analysis = a.sortVulnerabilitiesByCriticality()
	a.analysis = a.setDefaultVulnerabilityType()
	a.analysis = a.setDefaultConfidence()
	a.analysis = a.sortVulnerabilitiesByType()
	if !a.config.EnableInformationSeverity {
		a.analysis = a.removeInfoVulnerabilities()
	}
}

// nolint:gocyclo
func (a *Analyzer) checkIfNoExistHashAndLog(list []string) {
	for _, hash := range list {
		existing := false
		for idx := range a.analysis.AnalysisVulnerabilities {
			vulnHash := a.analysis.AnalysisVulnerabilities[idx].Vulnerability.VulnHash
			vulnHashInvalid := a.analysis.AnalysisVulnerabilities[idx].Vulnerability.VulnHashInvalid
			if hash == vulnHash || hash == vulnHashInvalid {
				existing = true
				break
			}
		}
		if !existing {
			logger.LogWarnWithLevel(messages.MsgWarnHashNotExistOnAnalysis + hash)
		}
	}
}

func (a *Analyzer) setFalsePositive() *analysis.Analysis {
	a.analysis = a.SetFalsePositivesAndRiskAcceptInVulnerabilities(
		a.config.FalsePositiveHashes, a.config.RiskAcceptHashes)

	a.checkIfNoExistHashAndLog(a.config.FalsePositiveHashes)
	a.checkIfNoExistHashAndLog(a.config.RiskAcceptHashes)
	return a.analysis
}

func (a *Analyzer) setAnalysisError(err error) {
	if err != nil {
		toAppend := ""
		if len(a.analysis.Errors) > 0 {
			a.analysis.Errors += "; " + err.Error()
			return
		}
		a.analysis.Errors += toAppend + err.Error()
	}
}

// SetFalsePositivesAndRiskAcceptInVulnerabilities set analysis vulnerabilities to false
// positive or risk accept if the hash exists on falsePositive and riskAccept params.
//
// nolint:lll
func (a *Analyzer) SetFalsePositivesAndRiskAcceptInVulnerabilities(falsePositive, riskAccept []string) *analysis.Analysis {
	for idx := range a.analysis.AnalysisVulnerabilities {
		a.setVulnerabilityType(
			&a.analysis.AnalysisVulnerabilities[idx].Vulnerability, falsePositive, enumsVulnerability.FalsePositive,
		)
		a.setVulnerabilityType(
			&a.analysis.AnalysisVulnerabilities[idx].Vulnerability, riskAccept, enumsVulnerability.RiskAccepted,
		)
	}
	return a.analysis
}

func (a *Analyzer) setVulnerabilityType(
	vuln *vulnerability.Vulnerability, hashes []string, vulnType enumsVulnerability.Type,
) {
	for _, hash := range hashes {
		hash = strings.TrimSpace(hash)
		// See vulnerability.Vulnerability.VulnHashInvalid docs for more info.
		if hash != "" && (strings.TrimSpace(vuln.VulnHash) == hash || strings.TrimSpace(vuln.VulnHashInvalid) == hash) {
			vuln.Type = vulnType
		}
	}
}

func (a *Analyzer) setAnalysisFinishedData() *analysis.Analysis {
	a.analysis.FinishedAt = time.Now()

	if a.analysis.HasErrors() {
		a.analysis.Status = enumsAnalysis.Error
		return a.analysis
	}

	a.analysis.Status = enumsAnalysis.Success
	return a.analysis
}

func (a *Analyzer) setupIDInAnalysisContents() *analysis.Analysis {
	for key := range a.analysis.AnalysisVulnerabilities {
		a.analysis.AnalysisVulnerabilities[key].SetCreatedAt()
		a.analysis.AnalysisVulnerabilities[key].SetAnalysisID(a.analysis.ID)
		a.analysis.AnalysisVulnerabilities[key].Vulnerability.VulnerabilityID = uuid.New()
	}
	return a.analysis
}

func (a *Analyzer) sortVulnerabilitiesByCriticality() *analysis.Analysis {
	analysisVulnerabilities := a.getVulnerabilitiesBySeverity(severities.Critical)
	analysisVulnerabilities = append(analysisVulnerabilities, a.getVulnerabilitiesBySeverity(severities.High)...)
	analysisVulnerabilities = append(analysisVulnerabilities, a.getVulnerabilitiesBySeverity(severities.Medium)...)
	analysisVulnerabilities = append(analysisVulnerabilities, a.getVulnerabilitiesBySeverity(severities.Low)...)
	analysisVulnerabilities = append(analysisVulnerabilities, a.getVulnerabilitiesBySeverity(severities.Unknown)...)
	analysisVulnerabilities = append(analysisVulnerabilities, a.getVulnerabilitiesBySeverity(severities.Info)...)
	a.analysis.AnalysisVulnerabilities = analysisVulnerabilities
	return a.analysis
}

func (a *Analyzer) sortVulnerabilitiesByType() *analysis.Analysis {
	analysisVulnerabilities := a.getVulnerabilitiesByType(enumsVulnerability.Vulnerability)
	analysisVulnerabilities = append(analysisVulnerabilities,
		a.getVulnerabilitiesByType(enumsVulnerability.RiskAccepted)...)
	analysisVulnerabilities = append(analysisVulnerabilities,
		a.getVulnerabilitiesByType(enumsVulnerability.FalsePositive)...)
	analysisVulnerabilities = append(analysisVulnerabilities,
		a.getVulnerabilitiesByType(enumsVulnerability.Corrected)...)
	a.analysis.AnalysisVulnerabilities = analysisVulnerabilities
	return a.analysis
}

func (a *Analyzer) getVulnerabilitiesByType(
	vulnType enumsVulnerability.Type) (response []analysis.AnalysisVulnerabilities) {
	for index := range a.analysis.AnalysisVulnerabilities {
		if a.analysis.AnalysisVulnerabilities[index].Vulnerability.Type == vulnType {
			response = append(response, a.analysis.AnalysisVulnerabilities[index])
		}
	}
	return response
}

func (a *Analyzer) getVulnerabilitiesBySeverity(
	search severities.Severity) (response []analysis.AnalysisVulnerabilities) {
	for index := range a.analysis.AnalysisVulnerabilities {
		if a.analysis.AnalysisVulnerabilities[index].Vulnerability.Severity == search {
			response = append(response, a.analysis.AnalysisVulnerabilities[index])
		}
	}
	return response
}

func (a *Analyzer) setDefaultVulnerabilityType() *analysis.Analysis {
	for key := range a.analysis.AnalysisVulnerabilities {
		a.analysis.AnalysisVulnerabilities[key].Vulnerability.Type = enumsVulnerability.Vulnerability
	}
	return a.analysis
}

func (a *Analyzer) setDefaultConfidence() *analysis.Analysis {
	for key := range a.analysis.AnalysisVulnerabilities {
		valid := false
		for _, conf := range confidence.Values() {
			if conf == a.analysis.AnalysisVulnerabilities[key].Vulnerability.Confidence {
				valid = true
				break
			}
		}
		if !valid {
			a.analysis.AnalysisVulnerabilities[key].Vulnerability.Confidence = confidence.Low
		}
	}
	return a.analysis
}

func (a *Analyzer) removeInfoVulnerabilities() *analysis.Analysis {
	var vulnerabilities []analysis.AnalysisVulnerabilities

	for index := range a.analysis.AnalysisVulnerabilities {
		if a.analysis.AnalysisVulnerabilities[index].Vulnerability.Severity != severities.Info {
			vulnerabilities = append(vulnerabilities, a.analysis.AnalysisVulnerabilities[index])
		}
	}

	a.analysis.AnalysisVulnerabilities = vulnerabilities

	return a.analysis
}

func (a *Analyzer) removeVulnerabilitiesBySeverity() *analysis.Analysis {
	var vulnerabilities []analysis.AnalysisVulnerabilities
	severitiesToIgnore := a.config.SeveritiesToIgnore

outer:
	for index := range a.analysis.AnalysisVulnerabilities {
		vuln := a.analysis.AnalysisVulnerabilities[index]
		for _, severity := range severitiesToIgnore {
			if strings.EqualFold(string(vuln.Vulnerability.Severity), severity) {
				continue outer
			}
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}
	a.analysis.AnalysisVulnerabilities = vulnerabilities
	return a.analysis
}

func (a *Analyzer) removeVulnerabilitiesByTypes() *analysis.Analysis {
	var vulnerabilities []analysis.AnalysisVulnerabilities

	for index := range a.analysis.AnalysisVulnerabilities {
		vulnType := a.analysis.AnalysisVulnerabilities[index].Vulnerability.Type
		for _, acceptedType := range a.config.ShowVulnerabilitiesTypes {
			if strings.EqualFold(vulnType.ToString(), acceptedType) {
				vulnerabilities = append(vulnerabilities, a.analysis.AnalysisVulnerabilities[index])
				break
			}
		}
	}

	a.analysis.AnalysisVulnerabilities = vulnerabilities

	return a.analysis
}

func newScanLoading(cfg *config.Config) *spinner.Spinner {
	loading := spinner.New(spinner.CharSets[11], LoadingDelay)
	loading.Suffix = messages.MsgInfoAnalysisLoading

	if cfg.LogLevel == logrus.DebugLevel.String() || cfg.LogLevel == logrus.TraceLevel.String() {
		loading.Writer = io.Discard
	}

	return loading
}
