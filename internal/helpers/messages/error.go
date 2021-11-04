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

package messages

// Block of messages usage into error response
const (
	MsgErrorPathNotValid                        = "invalid path:"
	MsgErrorJSONOutputFilePathNotValidExtension = "Output File path not valid file of type:"
	MsgErrorJSONOutputFilePathNotValidUnknown   = "Output File path is required or is invalid:"
	MsgErrorSeverityNotValid                    = "Type of severity not valid. See severities enable:"
	MsgErrorAskForUserCancelled                 = "Operation was canceled by user"
	MsgVulnerabilityTypeToShowInvalid           = "Error on validate vulnerability type is wrong type: "
	MsgErrorRunToolInDocker                     = "Something error went wrong in {{0}} tool " +
		"| analysisID -> {{1}} | output -> {{2}}\nError: %v"
	MsgErrorInvalidWorkDir           = "Workdir is nil! Check the configuration and try again"
	MsgErrorParseStringToToolsConfig = "Error when try parse tools config string to entity: %v. Using default values"
	MsgErrorNotFoundRequirementsTxt  = "Error The file requirements.txt not found in python project to " +
		"start analysis. It would be a good idea to commit it so horusec can check for vulnerabilities"
	MsgErrorPacketJSONNotFound = "Error It looks like your project doesn't have a package-lock.json " +
		"file. If you use NPM to handle your dependencies, it would be a good idea to commit it so horusec can check " +
		"for vulnerabilities"
	MsgErrorYarnLockNotFound = "Error It looks like your project doesn't have a yarn.lock file. " +
		"If you use Yarn to handle your dependencies, it would be a good idea to commit it so horusec " +
		"can check for vulnerabilities"
	MsgErrorYarnProcess     = "Error Yarn returned an error: "
	MsgErrorGemLockNotFound = "Error It looks like your project doesn't have a gemfile.lock file, " +
		"it would be a good idea to commit it so horusec can check for vulnerabilities"
	MsgErrorGetFilenameByExt = "Could not get filename by extension: %v"
)

// Block of messages usage into log of the level error
const (
	MsgErrorFalsePositiveNotValid        = "False positive is not valid because is duplicated in risk accept:"
	MsgErrorRiskAcceptNotValid           = "Risk Accept is not valid because is duplicated in false positive:"
	MsgErrorWhenCheckRequirementsGit     = "Error when check if git requirement it's ok!: %v"
	MsgErrorWhenCheckRequirementsDocker  = "Error when check if docker requirement it's ok: %v"
	MsgErrorWhenCheckDockerRunning       = "Error when check if docker is running: %v"
	MsgErrorWhenDockerIsLowerVersion     = "Your docker version is below of: %v"
	MsgErrorWhenGitIsLowerVersion        = "Your git version is below of: %v"
	MsgErrorInvalidConfigs               = "Errors on validate configuration: "
	MsgErrorRemoveAnalysisFolder         = "Error when remove analysis project inside .horusec"
	MsgErrorDetectLanguage               = "Error when detect language"
	MsgErrorCopyProjectToHorusecAnalysis = "Error when copy project to .horusec folder"
	MsgErrorGenerateJSONFile             = "Error when try parse horusec analysis to output"
	MsgErrorDockerPullImage              = "Error when pull new image: %v"
	MsgErrorDockerListImages             = "Error when list all images enable: %v"
	MsgErrorDockerCreateContainer        = "Error when create container of analysis: %v"
	MsgErrorDockerStartContainer         = "Error when start container of analysis: %v"
	MsgErrorDockerListAllContainers      = "Error when list all containers of analysis: %v"
	MsgErrorDockerRemoveContainer        = "Error when remove container of analysis: %v"
	MsgErrorGitCommitAuthorsExecute      = "Error when execute commit author command: %v"
	MsgErrorGitCommitAuthorsParseOutput  = "Error when to parse output %s to commit author struct: %v"
	MsgErrorParseStringToWorkDir         = "Error when try parse workdir string to entity: %v. Using default values"
	MsgErrorDeferFileClose               = "Error defer file close: "
	MsgErrorSetHeadersOnConfig           = "Error on set headers on configurations: %v"
	MsgErrorReplayWrong                  = "Error on set reply, Please type Y or N. Your current response was: "
	MsgErrorErrorOnCreateConfigFile      = "Error on create config file: %v"
	MsgErrorErrorOnReadConfigFile        = "Error on read config file on path %s: %v"
	MsgErrorFailedToPullImage            = "Failed to pull docker image %s: %v"
	MsgErrorWhileParsingCustomImages     = "Error when parsing custom images config: %v"
	MsgErrorSettingLogFile               = "Error when setting log file: %v"
)
