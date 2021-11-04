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

// Block of messages usage into log of the level debug
const (
	MsgDebugDockerAPIPullNewImage        = "Docker pull new image: "
	MsgDebugDockerAPIDownloadWithSuccess = "Docker download new image with success: "
	MsgDebugDockerAPIContainerCreated    = "Docker create new container: "
	MsgDebugDockerAPIContainerWait       = "Docker wait container up..."
	MsgDebugDockerAPIContainerRead       = "Docker read container output: "
	MsgDebugDockerAPIFinishedSuccess     = "Docker Finished analysis with SUCCESS: "
	MsgDebugDockerAPIFinishedError       = "Docker Finished analysis with ERROR: "
	MsgDebugToolStartAnalysis            = "Running {{0}} - {{1}} in analysisID: %s"
	MsgDebugToolFinishAnalysis           = "{{0}} - {{1}} is finished in analysisID: %s"
	MsgDebugOutputEmpty                  = "When format Output it's Empty!"
	MsgDebugConfigFileRunningOnPath      = "Config file running on path: %s"
	MsgDebugFolderOrFileIgnored          = "The file or folder was ignored to send analysis: %s"
	MsgDebugShowConfigs                  = "The current configuration for this analysis are: \n%s"
	MsgDebugShowWorkdir                  = "The workdir setup of tool %s for run in path: %s"
	MsgDebugToolIgnored                  = "The tool was ignored for run in this analysis: %s"
	MsgDebugVulnHashToFix                = "Vulnerability Hash expected to be FIXED: %s"
)
