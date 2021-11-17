package engine

import (
	"errors"
	"fmt"
	"io/fs"
	"os/user"
	"path/filepath"
	"plugin"
	"sync"
	"time"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/enums/images"
	"github.com/ZupIT/horusec/internal/services/docker"
	dockerClient "github.com/ZupIT/horusec/internal/services/docker/client"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/services/formatters/c/flawfinder"
	dotnetcli "github.com/ZupIT/horusec/internal/services/formatters/csharp/dotnet_cli"
	"github.com/ZupIT/horusec/internal/services/formatters/csharp/horuseccsharp"
	"github.com/ZupIT/horusec/internal/services/formatters/csharp/scs"
	"github.com/ZupIT/horusec/internal/services/formatters/dart/horusecdart"
	"github.com/ZupIT/horusec/internal/services/formatters/elixir/mixaudit"
	"github.com/ZupIT/horusec/internal/services/formatters/elixir/sobelow"
	dependencycheck "github.com/ZupIT/horusec/internal/services/formatters/generic/dependency_check"
	"github.com/ZupIT/horusec/internal/services/formatters/generic/semgrep"
	"github.com/ZupIT/horusec/internal/services/formatters/generic/trivy"
	"github.com/ZupIT/horusec/internal/services/formatters/go/gosec"
	"github.com/ZupIT/horusec/internal/services/formatters/go/nancy"
	"github.com/ZupIT/horusec/internal/services/formatters/hcl/checkov"
	"github.com/ZupIT/horusec/internal/services/formatters/hcl/tfsec"
	"github.com/ZupIT/horusec/internal/services/formatters/java/horusecjava"
	"github.com/ZupIT/horusec/internal/services/formatters/javascript/horusecnodejs"
	"github.com/ZupIT/horusec/internal/services/formatters/javascript/npmaudit"
	"github.com/ZupIT/horusec/internal/services/formatters/javascript/yarnaudit"
	"github.com/ZupIT/horusec/internal/services/formatters/kotlin/horuseckotlin"
	"github.com/ZupIT/horusec/internal/services/formatters/leaks/gitleaks"
	"github.com/ZupIT/horusec/internal/services/formatters/leaks/horusecleaks"
	"github.com/ZupIT/horusec/internal/services/formatters/nginx/horusecnginx"
	"github.com/ZupIT/horusec/internal/services/formatters/php/phpcs"
	"github.com/ZupIT/horusec/internal/services/formatters/python/bandit"
	"github.com/ZupIT/horusec/internal/services/formatters/python/safety"
	"github.com/ZupIT/horusec/internal/services/formatters/ruby/brakeman"
	"github.com/ZupIT/horusec/internal/services/formatters/ruby/bundler"
	"github.com/ZupIT/horusec/internal/services/formatters/shell/shellcheck"
	"github.com/ZupIT/horusec/internal/services/formatters/swift/horusecswift"
	"github.com/ZupIT/horusec/internal/services/formatters/yaml/horuseckubernetes"
)

type Plugin interface {
	Name() string
	Run() ([]vulnerability.Vulnerability, error)
}

// detectVulnerabilityFn is a func that detect vulnerabilities on path.
// detectVulnerabilityFn funcs run all in parallel, so a WaitGroup is required
// to synchronize states of running analysis.
//
// detectVulnerabilityFn funcs can also spawn other detectVulnerabilityFn funcs
// just passing the received WaitGroup to underlying funcs.
type detectVulnerabilityFn func(*sync.WaitGroup, string) error

type mapLanguagePlugins map[languages.Language][]Plugin

func loadPlugins() mapLanguagePlugins {
	plugins := make(mapLanguagePlugins, 0)

	user, err := user.Current()
	if err != nil {
		panic(fmt.Sprintf("can not get curret user: %v", err))
	}
	pluginsPath := filepath.Join(user.HomeDir, ".config", "horusec", "plugins")

	err = filepath.Walk(pluginsPath, func(path string, info fs.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}

		p, err := plugin.Open(path)
		if err != nil {
			panic(fmt.Sprintf("error to open plugin file %s: %v", path, err))
		}

		s, err := p.Lookup("Plugin")
		if err != nil {
			panic(fmt.Sprintf("error to find global variable Plugin on %s: %v", path, err))
		}
		plugin, ok := s.(Plugin)
		if !ok {
			panic(fmt.Sprintf("%s does not implement Plugin interface", path))
		}

		plugins[languages.Generic] = append(plugins[languages.Generic], plugin)

		return nil
	})
	if err != nil {
		panic(fmt.Sprintf("error to read plugins directory: %v", err))
	}

	return plugins
}

type Engine struct {
	docker    docker.Docker
	analysis  *analysis.Analysis
	config    *config.Config
	formatter formatters.IService
	plugins   mapLanguagePlugins
}

func New(cfg *config.Config, entity *analysis.Analysis) *Engine {
	dockerAPI := docker.New(dockerClient.NewDockerClient(), cfg, entity.ID)
	return &Engine{
		config:    cfg,
		docker:    dockerAPI,
		analysis:  entity,
		formatter: formatters.NewFormatterService(entity, dockerAPI, cfg),
		plugins:   loadPlugins(),
	}
}

func (e *Engine) Run(langs []languages.Language) error {
	if !e.config.DisableDocker {
		defer e.docker.DeleteContainersFromAPI()
	}
	return e.run(langs)
}

func (self *Engine) run(langs []languages.Language) error {
	errChan := make(chan error)

	funcs := self.detectVulnerabilityFuncs()

	go func() {
		for _, language := range langs {
			for _, subPath := range self.config.WorkDir.PathsOfLanguage(language) {
				if subPath != "" {
					logger.LogDebugWithLevel(
						fmt.Sprintf("Running %s in subpath: %s", language.ToString(), subPath),
					)
				}

				if plugins, exists := self.plugins[language]; exists {
					for _, plugin := range plugins {
						logger.LogInfo(fmt.Sprintf("Running plugin %s", plugin.Name()))
						vulns, err := plugin.Run()
						if err != nil {
							errChan <- err
							return
						}
						for _, vuln := range vulns {
							self.formatter.AddNewVulnerabilityIntoAnalysis(&vuln)
						}
					}

				}

				if fn, exist := funcs[language]; exist {
					// FIXME(matheus): This should be executed in parallel
					if err := fn(nil, subPath); err != nil {
						errChan <- err
						return
					}
				}
			}
		}
		errChan <- nil

	}()

	timeout := self.config.TimeoutInSecondsAnalysis
	timer := time.After(time.Duration(timeout) * time.Second)
	retry := self.config.MonitorRetryInSeconds
	tick := time.NewTicker(time.Duration(retry) * time.Second)
	defer tick.Stop()
	for {
		select {
		case err := <-errChan:
			return err
		case <-timer:
			self.docker.DeleteContainersFromAPI()
			self.config.IsTimeout = true
			return errors.New("timeout")
		case <-tick.C:
			timeout -= retry
		}
	}

}

// detectVulnerabilityFuncs returns a map of language and functions
// that detect vulnerabilities on some path.
//
// All Languages is greater than 15
//nolint:funlen
func (a *Engine) detectVulnerabilityFuncs() map[languages.Language]detectVulnerabilityFn {
	return map[languages.Language]detectVulnerabilityFn{
		languages.CSharp:     a.detectVulnerabilityCsharp,
		languages.Leaks:      a.detectVulnerabilityLeaks,
		languages.Go:         a.detectVulnerabilityGo,
		languages.Java:       a.detectVulnerabilityJava,
		languages.Kotlin:     a.detectVulnerabilityKotlin,
		languages.Javascript: a.detectVulnerabilityJavascript,
		languages.Python:     a.detectVulnerabilityPython,
		languages.Ruby:       a.detectVulnerabilityRuby,
		languages.HCL:        a.detectVulnerabilityHCL,
		languages.Generic:    a.detectVulnerabilityGeneric,
		languages.Yaml:       a.detectVulnerabilityYaml,
		languages.C:          a.detectVulnerabilityC,
		languages.PHP:        a.detectVulnerabilityPHP,
		languages.Dart:       a.detectVulnerabilityDart,
		languages.Elixir:     a.detectVulnerabilityElixir,
		languages.Shell:      a.detectVulnerabilityShell,
		languages.Nginx:      a.detectVulnerabilityNginx,
		languages.Swift:      a.detectVulneravilitySwift,
	}
}

func (a *Engine) detectVulneravilitySwift(_ *sync.WaitGroup, projectSubPath string) error {
	horusecswift.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Engine) detectVulnerabilityCsharp(wg *sync.WaitGroup, projectSubPath string) error {
	spawn(wg, horuseccsharp.NewFormatter(a.formatter), projectSubPath)

	if err := a.docker.PullImage(a.getCustomOrDefaultImage(languages.CSharp)); err != nil {
		return err
	}

	spawn(wg, scs.NewFormatter(a.formatter), projectSubPath)
	dotnetcli.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Engine) detectVulnerabilityLeaks(wg *sync.WaitGroup, projectSubPath string) error {
	spawn(wg, horusecleaks.NewFormatter(a.formatter), projectSubPath)

	if a.config.EnableGitHistoryAnalysis {
		if err := a.docker.PullImage(a.getCustomOrDefaultImage(languages.Leaks)); err != nil {
			return err
		}
		gitleaks.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	}

	return nil
}

func (a *Engine) detectVulnerabilityGo(wg *sync.WaitGroup, projectSubPath string) error {
	if err := a.docker.PullImage(a.getCustomOrDefaultImage(languages.Go)); err != nil {
		return err
	}

	spawn(wg, gosec.NewFormatter(a.formatter), projectSubPath)
	nancy.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Engine) detectVulnerabilityJava(_ *sync.WaitGroup, projectSubPath string) error {
	horusecjava.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Engine) detectVulnerabilityKotlin(_ *sync.WaitGroup, projectSubPath string) error {
	horuseckotlin.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Engine) detectVulnerabilityNginx(_ *sync.WaitGroup, projectSubPath string) error {
	horusecnginx.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Engine) detectVulnerabilityJavascript(wg *sync.WaitGroup, projectSubPath string) error {
	spawn(wg, horusecnodejs.NewFormatter(a.formatter), projectSubPath)

	if err := a.docker.PullImage(a.getCustomOrDefaultImage(languages.Javascript)); err != nil {
		return err
	}
	spawn(wg, yarnaudit.NewFormatter(a.formatter), projectSubPath)
	npmaudit.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Engine) detectVulnerabilityPython(wg *sync.WaitGroup, projectSubPath string) error {
	if err := a.docker.PullImage(a.getCustomOrDefaultImage(languages.Python)); err != nil {
		return err
	}
	spawn(wg, bandit.NewFormatter(a.formatter), projectSubPath)
	safety.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Engine) detectVulnerabilityRuby(wg *sync.WaitGroup, projectSubPath string) error {
	if err := a.docker.PullImage(a.getCustomOrDefaultImage(languages.Ruby)); err != nil {
		return err
	}
	spawn(wg, brakeman.NewFormatter(a.formatter), projectSubPath)
	bundler.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Engine) detectVulnerabilityHCL(wg *sync.WaitGroup, projectSubPath string) error {
	if err := a.docker.PullImage(a.getCustomOrDefaultImage(languages.HCL)); err != nil {
		return err
	}
	spawn(wg, tfsec.NewFormatter(a.formatter), projectSubPath)
	checkov.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Engine) detectVulnerabilityYaml(_ *sync.WaitGroup, projectSubPath string) error {
	horuseckubernetes.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Engine) detectVulnerabilityC(_ *sync.WaitGroup, projectSubPath string) error {
	if err := a.docker.PullImage(a.getCustomOrDefaultImage(languages.C)); err != nil {
		return err
	}
	flawfinder.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Engine) detectVulnerabilityPHP(_ *sync.WaitGroup, projectSubPath string) error {
	if err := a.docker.PullImage(a.getCustomOrDefaultImage(languages.PHP)); err != nil {
		return err
	}
	phpcs.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Engine) detectVulnerabilityGeneric(wg *sync.WaitGroup, projectSubPath string) error {
	if err := a.docker.PullImage(a.getCustomOrDefaultImage(languages.Generic)); err != nil {
		return err
	}

	spawn(wg, trivy.NewFormatter(a.formatter), projectSubPath)
	spawn(wg, semgrep.NewFormatter(a.formatter), projectSubPath)
	dependencycheck.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Engine) detectVulnerabilityDart(_ *sync.WaitGroup, projectSubPath string) error {
	horusecdart.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Engine) detectVulnerabilityElixir(wg *sync.WaitGroup, projectSubPath string) error {
	if err := a.docker.PullImage(a.getCustomOrDefaultImage(languages.Elixir)); err != nil {
		return err
	}
	spawn(wg, mixaudit.NewFormatter(a.formatter), projectSubPath)
	sobelow.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Engine) detectVulnerabilityShell(_ *sync.WaitGroup, projectSubPath string) error {
	if err := a.docker.PullImage(a.getCustomOrDefaultImage(languages.Shell)); err != nil {
		return err
	}
	shellcheck.NewFormatter(a.formatter).StartAnalysis(projectSubPath)
	return nil
}

func (a *Engine) getCustomOrDefaultImage(language languages.Language) string {
	// Images can be set to empty on config file, so we need to use only if its not empty.
	// If its empty we return the default value.
	if customImage := a.config.CustomImages[language]; customImage != "" {
		return customImage
	}
	return fmt.Sprintf("%s/%s", images.DefaultRegistry, images.MapValues()[language])
}

func spawn(wg *sync.WaitGroup, f formatters.IFormatter, src string) {
	// wg.Add(1)
	// go func() {
	// 	defer wg.Done()
	// 	f.StartAnalysis(src)
	// }()
	f.StartAnalysis(src)
}
