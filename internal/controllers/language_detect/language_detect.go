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

package languagedetect

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	doubleStar "github.com/bmatcuk/doublestar/v4"
	"github.com/go-enry/go-enry/v2"
	"github.com/google/uuid"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/enums/toignore"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/utils/copy"
)

type LanguageDetect struct {
	configs    *config.Config
	analysisID uuid.UUID
}

func NewLanguageDetect(configs *config.Config, analysisID uuid.UUID) *LanguageDetect {
	return &LanguageDetect{
		analysisID: analysisID,
		configs:    configs,
	}
}

func (ld *LanguageDetect) Detect(directory string) ([]languages.Language, error) {
	langs := []string{languages.Leaks.ToString(), languages.Generic.ToString()}
	languagesFound, err := ld.getLanguages(directory)
	if err != nil {
		log.Errorf(messages.MsgErrorDetectLanguage, err)
		return nil, err
	}

	langs = ld.appendLanguagesFound(langs, languagesFound)

	err = ld.copyProjectToHorusecFolder(directory)
	return ld.filterSupportedLanguages(langs), err
}

func (ld *LanguageDetect) getLanguages(directory string) (languagesFound []string, err error) {
	filesToSkip, languagesFound, err := ld.walkInPathAndReturnTotalToSkip(directory)
	if filesToSkip > 0 {
		log.Warnf(messages.MsgWarnTotalFolderOrFileWasIgnored, filesToSkip)
	}
	return ld.uniqueLanguages(languagesFound), err
}

func (ld *LanguageDetect) walkInPathAndReturnTotalToSkip(
	directory string) (totalToSkip int, languagesFound []string, err error) {
	err = filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		currentLanguagesFound, skip := ld.execWalkToGetLanguagesAndReturnIfSkip(path, info)
		if skip {
			totalToSkip++
		}
		languagesFound = ld.appendLanguagesFound(languagesFound, currentLanguagesFound)
		return nil
	})
	return totalToSkip, languagesFound, err
}

func (ld *LanguageDetect) execWalkToGetLanguagesAndReturnIfSkip(
	path string, info os.FileInfo) (languagesFound []string, skip bool) {
	skip = ld.filesAndFoldersToIgnore(path)
	if skip {
		log.Debugf(messages.MsgDebugFolderOrFileIgnored, filepath.Clean(path))
	}
	if !info.IsDir() && !skip {
		newLanguages := enry.GetLanguages(path, nil)
		log.WithFields(log.Fields{
			"path":      path,
			"languages": newLanguages,
		}).Debug(messages.MsgTraceLanguageFound)

		languagesFound = append(languagesFound, newLanguages...)
	}
	return languagesFound, skip
}

func (ld *LanguageDetect) uniqueLanguages(languagesFound []string) (output []string) {
	for _, language := range languagesFound {
		if len(output) == 0 {
			output = append(output, language)
		} else {
			output = ld.checkIfLanguageExistAndConcat(output, language)
		}
	}
	return output
}

func (ld *LanguageDetect) checkIfLanguageExistAndConcat(output []string, language string) []string {
	existing := false
	for _, appended := range output {
		if appended == language {
			existing = true
			break
		}
	}
	if !existing {
		output = append(output, language)
	}
	return output
}

func (ld *LanguageDetect) filesAndFoldersToIgnore(path string) bool {
	isToSkip := ld.checkDefaultPathsToIgnore(path) ||
		ld.checkAdditionalPathsToIgnore(path) ||
		ld.checkFileExtensionInvalid(path)
	return isToSkip
}

func (ld *LanguageDetect) checkDefaultPathsToIgnore(path string) bool {
	for _, value := range toignore.GetDefaultFoldersToIgnore() {
		if strings.Contains(path, value) {
			return true
		}
	}
	if !ld.configs.EnableGitHistoryAnalysis {
		return strings.Contains(path, ".git")
	}
	return false
}

func (ld *LanguageDetect) checkAdditionalPathsToIgnore(path string) bool {
	for _, value := range ld.configs.FilesOrPathsToIgnore {
		matched, _ := doubleStar.Match(strings.TrimSpace(value), path)
		if matched {
			return true
		}
	}
	return false
}

func (ld *LanguageDetect) checkFileExtensionInvalid(path string) bool {
	extensionFound := filepath.Ext(path)
	for _, value := range toignore.GetDefaultExtensionsToIgnore() {
		if strings.EqualFold(value, extensionFound) {
			return true
		}
	}
	return false
}

func (ld *LanguageDetect) copyProjectToHorusecFolder(directory string) error {
	folderDstName := filepath.Join(directory, ".horusec", ld.analysisID.String())
	err := copy.Copy(directory, folderDstName, ld.filesAndFoldersToIgnore)
	if err != nil {
		log.Errorf(messages.MsgErrorCopyProjectToHorusecAnalysis, err)
	} else {
		log.Warnf(messages.MsgWarnMonitorTimeoutIn, ld.configs.TimeoutInSecondsAnalysis)
		log.Warnf(messages.MsgWarnDontRemoveHorusecFolder, folderDstName)
	}
	return err
}

func (ld *LanguageDetect) filterSupportedLanguages(langs []string) (onlySupportedLangs []languages.Language) {
	for _, lang := range langs {
		if ld.isSupportedLanguage(lang) {
			onlySupportedLangs = append(onlySupportedLangs, languages.ParseStringToLanguage(lang))
		}
	}

	return onlySupportedLangs
}

func (ld *LanguageDetect) isSupportedLanguage(langName string) bool {
	for _, lang := range languages.Values() {
		if langName == lang.ToString() {
			return true
		}
	}

	return false
}

func (ld *LanguageDetect) appendLanguagesFound(existingLanguages, languagesFound []string) []string {
	for _, lang := range languagesFound {
		existingLanguages = ld.updateExistingLanguages(lang, existingLanguages)
	}

	return ld.uniqueLanguages(existingLanguages)
}

func (ld *LanguageDetect) updateExistingLanguages(lang string, existingLanguages []string) []string {
	switch {
	case ld.isTypescriptOrJavascriptLang(lang):
		return append(existingLanguages, languages.Javascript.ToString())
	case ld.isCPlusPLusOrCLang(lang):
		return append(existingLanguages, languages.C.ToString())
	case ld.isBatFileOrShellFile(lang):
		return append(existingLanguages, languages.Shell.ToString())
	default:
		return append(existingLanguages, lang)
	}
}

func (ld *LanguageDetect) isTypescriptOrJavascriptLang(lang string) bool {
	return strings.EqualFold(lang, languages.Javascript.ToString()) ||
		strings.EqualFold(lang, languages.Typescript.ToString()) ||
		strings.EqualFold(lang, "TSX") ||
		strings.EqualFold(lang, "JSX")
}

func (ld *LanguageDetect) isCPlusPLusOrCLang(lang string) bool {
	return strings.EqualFold(lang, "C++") ||
		strings.EqualFold(lang, "C")
}

func (ld *LanguageDetect) isBatFileOrShellFile(lang string) bool {
	return strings.EqualFold(lang, "Batchfile") ||
		strings.EqualFold(lang, "Shell")
}
