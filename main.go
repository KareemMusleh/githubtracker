package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

var BBOUNTY_PATH string = "/hdd/home/me/bbounty/"
var GITHUB_TOKEN string = os.Getenv("GITHUB_TOKEN")
var HACKERONE_TOKEN string = os.Getenv("HACKERONE_TOKEN")
var HACKERONE_USERNAME string = "zxcv_enjoyer"
var TRACKER_DIR string = ".GITHUB_STALKER"
var OUTPUT_DIR string = "output"

// IPv6 is copied from https://vernon.mauery.com/content/2008/04/21/ipv6-regex/
// IPv4 is copied from https://stackoverflow.com/questions/5284147/validating-ipv4-addresses-with-regexp
var ipRegexes = []string{
	`((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}`,
	`(A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,6}Z)|(A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}Z)|(A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}Z)|(A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}Z)|(A([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}Z)|(A([0-9a-f]{1,4}:){1,6}(:[0-9a-f]{1,4}){1,1}Z)|(A(([0-9a-f]{1,4}:){1,7}|:):Z)|(A:(:[0-9a-f]{1,4}){1,7}Z)|(A((([0-9a-f]{1,4}:){6})(25[0-5]|2[0-4]d|[0-1]?d?d)(.(25[0-5]|2[0-4]d|[0-1]?d?d)){3})Z)|(A(([0-9a-f]{1,4}:){5}[0-9a-f]{1,4}:(25[0-5]|2[0-4]d|[0-1]?d?d)(.(25[0-5]|2[0-4]d|[0-1]?d?d)){3})Z)|(A([0-9a-f]{1,4}:){5}:[0-9a-f]{1,4}:(25[0-5]|2[0-4]d|[0-1]?d?d)(.(25[0-5]|2[0-4]d|[0-1]?d?d)){3}Z)|(A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,4}:(25[0-5]|2[0-4]d|[0-1]?d?d)(.(25[0-5]|2[0-4]d|[0-1]?d?d)){3}Z)|(A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,3}:(25[0-5]|2[0-4]d|[0-1]?d?d)(.(25[0-5]|2[0-4]d|[0-1]?d?d)){3}Z)|(A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,2}:(25[0-5]|2[0-4]d|[0-1]?d?d)(.(25[0-5]|2[0-4]d|[0-1]?d?d)){3}Z)|(A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,1}:(25[0-5]|2[0-4]d|[0-1]?d?d)(.(25[0-5]|2[0-4]d|[0-1]?d?d)){3}Z)|(A(([0-9a-f]{1,4}:){1,5}|:):(25[0-5]|2[0-4]d|[0-1]?d?d)(.(25[0-5]|2[0-4]d|[0-1]?d?d)){3}Z)|(A:(:[0-9a-f]{1,4}){1,5}:(25[0-5]|2[0-4]d|[0-1]?d?d)(.(25[0-5]|2[0-4]d|[0-1]?d?d)){3}Z)`,
}
var secretRegexes = []string{
	`cloudinary://.*`,
	`.*firebaseio\.com`,
	`(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})`,
	`-----BEGIN RSA PRIVATE KEY-----`,
	`-----BEGIN DSA PRIVATE KEY-----`,
	`-----BEGIN EC PRIVATE KEY-----`,
	`-----BEGIN PGP PRIVATE KEY BLOCK-----`,
	`AKIA[0-9A-Z]{16}`,
	`amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,
	`EAACEdEose0cBA[0-9A-Za-z]+`,
	`[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]`,
	`[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]`,
	`[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]`,
	`[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]`,
	`AIza[0-9A-Za-z\\-_]{35}`,
	`[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com`,
	`\"type\": \"service_account\"`,
	`ya29\\.[0-9A-Za-z\\-_]+`,
	`[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`,
	`[0-9a-f]{32}-us[0-9]{1,2}`,
	`key-[0-9a-zA-Z]{32}`,
	`[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]`,
	`access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}`,
	`sk_live_[0-9a-z]{32}`,
	`https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`,
	`sk_live_[0-9a-zA-Z]{24}`,
	`rk_live_[0-9a-zA-Z]{24}`,
	`sq0atp-[0-9A-Za-z\\-_]{22}`,
	`sq0atp-[0-9A-Za-z\\-_]{43}`,
	`SK[0-9a-fA-F]{32}`,
	`[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}`,
	`[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]`,
}

// Url regex is originally from https://github.com/validatorjs/validator.js
var urlRegex string = `(?!mailto:)(?:(?:\w+)://)?(?:\\S+(?::\\S*)?@)?(?:(?:(?:[1-9]\\d?|1\\d\\d|2[01]\\d|22[0-3])(?:\\.(?:1?\\d{1,2}|2[0-4]\\d|25[0-5])){2}(?:\\.(?:[0-9]\\d?|1\\d\\d|2[0-4]\\d|25[0-4]))|(?:(?:[a-z\\u00a1-\\uffff0-9]+-?)*[a-z\\u00a1-\\uffff0-9]+)(?:\\.(?:[a-z\\u00a1-\\uffff0-9]+-?)*[a-z\\u00a1-\\uffff0-9]+)*(?:\\.(?:[a-z\\u00a1-\\uffff]{2,})))|localhost)(?::\\d{2,5})?(?:(/|\\?|#)[^\\s]*)?`

type Repository struct {
	Name     string `json:"name"`
	CloneURL string `json:"clone_url"`
	Fork     bool   `json:"fork"`
}

type StructuredScope struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		AssetType                  string    `json:"asset_type"`
		AssetIdentifier            string    `json:"asset_identifier"`
		EligibleForBounty          bool      `json:"eligible_for_bounty"`
		EligibleForSubmission      bool      `json:"eligible_for_submission"`
		Instruction                *string   `json:"instruction"`
		MaxSeverity                string    `json:"max_severity"`
		CreatedAt                  time.Time `json:"created_at"`
		UpdatedAt                  time.Time `json:"updated_at"`
		ConfidentialityRequirement *string   `json:"confidentiality_requirement,omitempty"`
		IntegrityRequirement       *string   `json:"integrity_requirement,omitempty"`
		AvailabilityRequirement    *string   `json:"availability_requirement,omitempty"`
	} `json:"attributes"`
}

type Links struct {
	Self  string `json:"self"`
	Next  string `json:"next"`
	Prev  string `json:"prev"`
	First string `json:"first"`
	Last  string `json:"last"`
}

type Response struct {
	Data  []StructuredScope `json:"data"`
	Links Links             `json:"links"`
}

//	curl "https://api.hackerone.com/v1/programs/{id}/structured_scopes" \
//	  -X GET \
//	  -u "<YOUR_API_USERNAME>:<YOUR_API_TOKEN>" \
//	  -H 'Accept: application/json'
func GetWildcards(programName string) ([]string, error) {
	var wildcards []string
	apiURL := fmt.Sprintf("https://api.hackerone.com/v1/hackers/programs/%s/structured_scopes", programName)
	req, err := http.NewRequest("GET", "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create a new GET request: %v", err)
	}
	req.SetBasicAuth(HACKERONE_USERNAME, HACKERONE_TOKEN)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("User-Agent", "GOLANG")
	client := &http.Client{}

	for {
		req.URL, err = url.ParseRequestURI(apiURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse request url %s: %v", apiURL, err)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to send request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected response status: %d", resp.StatusCode)
		}

		var program Response
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %v", err)
		}

		err = json.Unmarshal(body, &program)
		if err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %v", err)
		}

		for _, scope := range program.Data {
			// fmt.Println(scope)
			if scope.Attributes.AssetType == "WILDCARD" && scope.Attributes.EligibleForBounty {
				wildcards = append(wildcards, scope.Attributes.AssetIdentifier)
			}
		}
		if program.Links.Next == "" {
			break
		} else {
			apiURL = program.Links.Next
		}
	}
	return wildcards, nil
}
func CreateWildcardRegexes(wildcards []string) ([]string, error) {
	// The returned regexs divide the URI into 4 parts
	// protocol, subdomain, port, directory
	var regexes []string
	for _, wildcard := range wildcards {
		if wildcard[:2] != "*." || strings.Count(wildcard, "*") != 1 {
			return nil, fmt.Errorf("non-standard wildcard %v", wildcard)
		}
		wildcard = strings.ReplaceAll(wildcard, ".", `\.`)
		regex := fmt.Sprintf("(?:(\\w+)://)?((?:[a-zA-Z0-9._%%+-]+)?%s)(?::?(\\d+))?(/[/a-zA-Z0-9._%%+-]*)?", wildcard[3:])
		regexes = append(regexes, regex)
	}
	return regexes, nil
}
func fileExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false // some other error
}

func GetGithubRepos(username string, perPage, pageIndex int) (*http.Response, error) {
	apiURL := fmt.Sprintf("https://api.github.com/users/%s/repos?per_page=%v&page=%v", username, perPage, pageIndex)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create a new GET request: %v", err)
	}
	req.Header = http.Header{
		"User-Agent":           {"GOLANG"},
		"Authorization":        {"Bearer " + GITHUB_TOKEN},
		"X-GitHub-Api-Version": {"2022-11-28"},
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()
	return resp, nil
}
func InitGithubClone(username string, initForks bool, options ...int) error {
	var perPage, maxTries int
	if len(options) > 0 { // the default value for per_page
		perPage = options[0]
	} else {
		perPage = 10
	}
	if len(options) > 1 {
		maxTries = options[1]
	} else {
		maxTries = 10
	}
	userDir := GetUserPath(username)
	pageIndex := 1
	for {
		fmt.Printf("Looking at page %v\n", pageIndex)
		resp, err := GetGithubRepos(username, perPage, pageIndex)
		if err != nil {
			return fmt.Errorf("failed to fetch repositories: %v", err)
		}

		var repos []Repository
		if err := json.NewDecoder(resp.Body).Decode(&repos); err != nil {
			return fmt.Errorf("failed to parse response: %v", err)
		}

		for _, repo := range repos {
			if !initForks && repo.Fork {
				continue
			}
			clonePath := filepath.Join(userDir, repo.Name)
			if fileExists(clonePath) {
				continue
			}

			for try := 0; try < maxTries; try++ {
				_, err := git.PlainClone(clonePath, false, &git.CloneOptions{
					URL: repo.CloneURL,
				})
				if err != nil {
					// log.Printf("failed to clone repository %s: %v", repo.Name, err)
					// TODO. Find the issue with git that results in it not being able to download large git repos
					break
					// _ = os.RemoveAll(clonePath) // Sometimes the path stays after a cloning error
				} else {
					break
				}
			}
		}
		resp.Body.Close()
		if len(repos) < perPage {
			break
		}
		pageIndex++
	}
	return nil
}

// GitCatFile is a function to replicate `git cat-file -p <object>` functionality.
func ReadBlob(repoDir, objectID string) ([]byte, error) {
	// Open the repository.
	repo, err := git.PlainOpen(repoDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	// Resolve the object hash.
	hash := plumbing.NewHash(objectID)

	// Retrieve the object.
	obj, err := repo.BlobObject(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to find object %s: %w", objectID, err)
	}
	content := make([]byte, obj.Size)
	if obj.Size == 0 {
		return content, nil
	}
	reader, err := obj.Reader()
	if err != nil {
		return nil, fmt.Errorf("failed to create a reader: %w", err)
	}
	defer reader.Close()
	_, err = reader.Read(content)
	if err != nil {
		fmt.Println(repoDir, objectID, obj.Size)
		return nil, fmt.Errorf("failed to read blob content: %w", err)
	}
	return content, nil
}

// Return a list of all blobs that correspond to a particular repo dir
// Probaby will have to replace this later with a smarter method
func GetRepoBlobs(repoDir string) ([]string, error) {
	repo, err := git.PlainOpen(repoDir)
	var repoBlobs []string
	if err != nil {
		return repoBlobs, err
	}

	repoTrees, err := repo.TreeObjects()
	if err != nil {
		return repoBlobs, err
	}

	seenBefore := make(map[string]bool)
	for {
		tree, err := repoTrees.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return repoBlobs, err
		}
		files := tree.Files()
		for {
			blob, err := files.Next()
			if err != nil {
				if err == io.EOF {
					break
				}
				return repoBlobs, err
			}
			id := blob.ID().String()
			if !seenBefore[id] {
				seenBefore[id] = true
				repoBlobs = append(repoBlobs, id)
			}
		}
	}
	return repoBlobs, nil
}

func defaultError(err error) {
	log.Fatalf("Error: %v", err)
}
func GetUserPath(user string) string {
	return filepath.Join(BBOUNTY_PATH, user, "github")
}

func GetTrackerPath(user string, repo string) string {
	return filepath.Join(BBOUNTY_PATH, user, "github", repo, TRACKER_DIR)
}

func searchGithubRepo(githubUser string, githubRepo string, regexes []string, T int) ([]string, error) {
	var results []string
	trackerPath := GetTrackerPath(githubUser, githubRepo)
	blobs, err := os.ReadDir(trackerPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read dir %s: %v", trackerPath, err)
	}

	// Create a buffered channel to limit concurrent goroutines
	semaphore := make(chan struct{}, T)
	resultsChan := make(chan []string, len(blobs))
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, blob := range blobs {
		if !blob.IsDir() {
			wg.Add(1)
			go func(blob os.DirEntry) {
				defer wg.Done()
				// Acquire a semaphore slot
				semaphore <- struct{}{}
				defer func() { <-semaphore }() // Release the slot when done

				filePath := filepath.Join(trackerPath, blob.Name())
				content, err := os.ReadFile(filePath)
				if err != nil {
					fmt.Printf("failed to read file %s: %v\n", filePath, err)
					return
				}
				contentStr := string(content)
				var localMatches []string
				for _, regex := range regexes {
					re := regexp.MustCompile(regex)
					matches := re.FindAllString(contentStr, -1)
					localMatches = append(localMatches, matches...)
				}
				if len(localMatches) > 0 {
					resultsChan <- localMatches
				}
			}(blob)
		}
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for matches := range resultsChan {
		mu.Lock()
		results = append(results, matches...)
		mu.Unlock()
	}

	return results, nil
}
func TrackUser(username string) error {
	userDir := GetUserPath(username)
	gitRepos, err := os.ReadDir(userDir)
	if err != nil {
		return fmt.Errorf("failed to read dir %s: %v", userDir, err)
	}
	for _, gitRepo := range gitRepos {
		// fmt.Println("Tracking", gitRepo.Name())
		if !gitRepo.IsDir() {
			continue
		}
		repoDir := filepath.Join(userDir, gitRepo.Name())
		repoBlobs, err := GetRepoBlobs(repoDir)
		if err != nil {
			return fmt.Errorf("failed to get repo blobs for %s: %v", repoDir, err)
		}
		currTrackerDir := filepath.Join(userDir, gitRepo.Name(), TRACKER_DIR)
		err = os.Mkdir(currTrackerDir, 0777)
		if err != nil && !os.IsExist(err) {
			return fmt.Errorf("failed to create a directory: %v", err)
		}
		for _, blob_id := range repoBlobs {
			blobContent, err := ReadBlob(repoDir, blob_id)
			if err != nil {
				return fmt.Errorf("failed read blob: %v", err)
			}
			if fileExists(filepath.Join(currTrackerDir, blob_id)) {
				continue
			}
			err = os.WriteFile(filepath.Join(currTrackerDir, blob_id), blobContent, 0660)
			if err != nil && !os.IsExist(err) {
				return fmt.Errorf("failed to write file: %v", err)
			}
		}
	}
	return nil
}

func GetBlobsUser(username string) ([]string, error) {
	var blobPaths []string
	userDir := GetUserPath(username)
	gitRepos, err := os.ReadDir(userDir)
	if err != nil {
		return blobPaths, fmt.Errorf("failed to read dir %s: %v", userDir, err)
	}
	for _, gitRepo := range gitRepos {
		// fmt.Println("Tracking", gitRepo.Name())
		if gitRepo.IsDir() {
			continue
		}
		blobDir := filepath.Join(userDir, gitRepo.Name(), TRACKER_DIR)
		blobs, err := os.ReadDir(blobDir)
		if err != nil {
			continue
		}
		for _, blob := range blobs {
			blobPaths = append(blobPaths, filepath.Join(blob.Name()))
		}
	}
	return blobPaths, nil
}
func writeToFile(filename string, data []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range data {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return err
		}
	}
	return writer.Flush()
}
func writeToFileSet(filename string, data map[string]struct{}) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for line := range data {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return err
		}
	}
	return writer.Flush()
}
func SearchUser(githubName string, regexes []string) error {
	userDir := GetUserPath(githubName)
	repos, _ := os.ReadDir(userDir)
	var set map[string]struct{}
	for i, repo := range repos {
		repoDir := filepath.Join(OUTPUT_DIR, repo.Name())
		err := os.Mkdir(repoDir, 0777)
		if err != nil && !os.IsExist(err) {
			return fmt.Errorf("failed to create a directory: %v", err)
		}
		var subdomains []string
		var dirs []string
		fmt.Println(i, len(repos), repo.Name())
		results, _ := searchGithubRepo(githubName, repo.Name(), regexes, 40)
		set = make(map[string]struct{})
		for _, result := range results {
			set[result] = struct{}{}
		}
		for key := range set {
			for _, regex := range regexes {
				re := regexp.MustCompile(regex)
				match := re.FindStringSubmatch(key)
				if len(match) == 0 {
					continue
				}
				subdomains = append(subdomains, match[2])
				dirs = append(dirs, match[4])
			}
		}
		err = writeToFile(repoDir+"/subdomains.txt", subdomains)
		if err != nil {
			log.Fatalf("Failed to write subdomains: %v", err)
		}
		err = writeToFile(repoDir+"/dirs.txt", dirs)
		if err != nil {
			log.Fatalf("Failed to write subdomains: %v", err)
		}
		_ = writeToFileSet(repoDir+"/all.txt", set)
	}
	return nil
}
func main() {
	hackeroneName := "reddit"
	githubName := "reddit"
	wildcards, err := GetWildcards(hackeroneName)
	if err != nil {
		defaultError(err)
	}
	scopeRegexes, _ := CreateWildcardRegexes(wildcards)
	err = SearchUser(githubName, scopeRegexes)
	if err != nil {
		defaultError(err)
	}
}
