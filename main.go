package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
	"strings"
	"regexp"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

type Repository struct {
	Name     string `json:"name"`
	CloneURL string `json:"clone_url"`
	Fork     bool   `json:"fork"`
}

var BBOUNTY_PATH string = "/home/me/bbounty/"
var GITHUB_TOKEN string = os.Getenv("GITHUB_TOKEN")
var HACKERONE_TOKEN string = os.Getenv("HACKERONE_TOKEN")
var HACKERONE_USERNAME string = "zxcv_enjoyer"
var trackerDirName string = ".GITHUB_TRACKER"

type StructuredScope struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Attributes struct {
		AssetType          string    `json:"asset_type"`
		AssetIdentifier    string    `json:"asset_identifier"`
		EligibleForBounty  bool      `json:"eligible_for_bounty"`
		EligibleForSubmission bool   `json:"eligible_for_submission"`
		Instruction        *string   `json:"instruction"`
		MaxSeverity        string    `json:"max_severity"`
		CreatedAt          time.Time `json:"created_at"`
		UpdatedAt          time.Time `json:"updated_at"`
		ConfidentialityRequirement *string `json:"confidentiality_requirement,omitempty"`
		IntegrityRequirement       *string `json:"integrity_requirement,omitempty"`
		AvailabilityRequirement    *string `json:"availability_requirement,omitempty"`
	} `json:"attributes"`
}

type Links struct {
	Self  string `json:"self"`
	Next string `json:"next"`
	Prev  string `json:"prev"`
	First string `json:"first"`
	Last string `json:"last"`
}

type Response struct {
	Data  []StructuredScope `json:"data"`
	Links Links             `json:"links"`
}


// curl "https://api.hackerone.com/v1/programs/{id}/structured_scopes" \
//   -X GET \
//   -u "<YOUR_API_USERNAME>:<YOUR_API_TOKEN>" \
//   -H 'Accept: application/json'
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
	if err != nil {
		return nil, fmt.Errorf("failed to fetch program details: %v", err)
	}

	for {
		req.URL, err = url.ParseRequestURI(apiURL)
		if (err != nil) {
			return nil, fmt.Errorf("failed to parse request url %s: %v", apiURL, err)
		}
		resp, err := client.Do(req)
		if (err != nil) {
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
		if (program.Links.Next == "") {
			break
		} else {
			apiURL = program.Links.Next
		}
	}
	return wildcards, nil
}
func CreateWildcardsRegexps(wildcards []string) ([]string, error) {
	// The returned regexps divide the URI into 4 parts
	// protocol, subdomain, port, directory
	var regexps []string
	for _, wildcard := range wildcards {
		if (wildcard[:2] != "*." || strings.Count(wildcard, "*") != 1) {
			return nil, fmt.Errorf("non-standard wildcard %v", wildcard)
		}
		wildcard = strings.ReplaceAll(pattern, ".", "\.")
		regexp := fmt.Sprintf("(?:(\S+)://)?((?:[a-zA-Z0-9._%+-]+\\.)?%s)(?::?(\\d+))?(/[/a-zA-Z0-9._%+-]*)?", wildcard[2:])
		regexps = append(regexps, regexp)
	}
	return regexps, nil
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
	if (err != nil) {
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
	userDir := GetUserDir(username)
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
			fmt.Println(clonePath)
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
func GetUserDir(username string) string {
	return filepath.Join(BBOUNTY_PATH, username, "github")
}
func TrackUser(username string) error {
	userDir := GetUserDir(username)
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
		currTrackerDir := filepath.Join(userDir, gitRepo.Name(), trackerDirName)
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
// func main() {
// 	username := "roblox"
// 	if err := InitGithubClone(username, false); err != nil {
// 		defaultError(err)
// 	}
// 	err := TrackUser(username)
// 	if err != nil {
// 		defaultError(err)
// 	}
// 	// pattern := `\b[a-zA-Z0-9._%+-]+\.snooguts\.net\b`
// 	// SearchUser(username, pattern)
// }

func main() {
	// programName := "reddit"
	// domains, err := GetWildcardDomains(programName)
	// if err != nil {
		// fmt.Println("Error:", err)
		// return
	// }
	// fmt.Println("Wildcard Domains:", domains)
	// wildcard := "*.redditinc.com"
	// pattern := strings.ReplaceAll(wildcard, "*", "[a-zA-Z0-9._%+-]+")
	// pattern := strings.ReplaceAll(wildcard, ".", "\\.")
	if (wildcard[:2] != "*." || strings.Count(wildcard, "*") != 1) {
		return nil, fmt.Errorf("non-standard wildcard %v", wildcard)
	}
	pattern := "(?:(https?)://)?((?:[a-zA-Z0-9._%+-]+\\.)?redditinc.com)(?::?(\\d+))?(/[/a-zA-Z0-9._%+-]*)?"
	pattern = strings.ReplaceAll(pattern, "", "")
	re := regexp.MustCompile(pattern)
	testStrings := []string{
		"www.redditinc.com/asdf",
		"sub.redditinc.com:8000",
		"redditinc.com",
		"https://www.redditinc.com:8443/asdf/asdf.php",
		"otherdomain.com",
	}
	for _, test := range testStrings {
		match := re.FindStringSubmatch(test)
		if len(match) != 0 {
		fmt.Printf("Match %s: %v %v\n", test, match, len(match))
		}
	}
}