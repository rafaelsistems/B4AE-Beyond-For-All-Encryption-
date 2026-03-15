# B4AE Docker Build and Publish Script
# Version: 2.0.0
# Description: Automates Docker image build and publish to GitHub Container Registry

param(
    [string]$Version = "2.0.0",
    [string]$GithubUser = "rafaelsistems",
    [string]$ImageName = "b4ae",
    [switch]$SkipBuild,
    [switch]$SkipPush,
    [switch]$Help
)

# Color output functions
function Write-Success { Write-Host $args -ForegroundColor Green }
function Write-Info { Write-Host $args -ForegroundColor Cyan }
function Write-Warning { Write-Host $args -ForegroundColor Yellow }
function Write-Error { Write-Host $args -ForegroundColor Red }

# Help message
if ($Help) {
    Write-Host @"
B4AE Docker Build and Publish Script

USAGE:
    .\docker-publish.ps1 [OPTIONS]

OPTIONS:
    -Version <version>      Version tag (default: 2.0.0)
    -GithubUser <user>      GitHub username (default: rafaelsistems)
    -ImageName <name>       Image name (default: b4ae)
    -SkipBuild             Skip the build step
    -SkipPush              Skip the push step
    -Help                  Show this help message

EXAMPLES:
    .\docker-publish.ps1
    .\docker-publish.ps1 -Version 2.1.0
    .\docker-publish.ps1 -SkipBuild
    .\docker-publish.ps1 -SkipPush

PREREQUISITES:
    1. Docker Desktop must be running
    2. GITHUB_TOKEN environment variable must be set
    3. Token must have 'write:packages' scope

"@
    exit 0
}

Write-Info "=== B4AE Docker Build and Publish ==="
Write-Info "Version: $Version"
Write-Info "Registry: ghcr.io/$GithubUser/$ImageName"
Write-Info ""

# Check if Docker is running
Write-Info "Checking Docker status..."
try {
    $dockerVersion = docker version --format '{{.Server.Version}}' 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Docker Desktop is not running!"
        Write-Warning "Please start Docker Desktop and try again."
        exit 1
    }
    Write-Success "Docker is running (version: $dockerVersion)"
} catch {
    Write-Error "Docker is not available!"
    Write-Warning "Please install Docker Desktop and try again."
    exit 1
}

# Check for GITHUB_TOKEN
if (-not $SkipPush) {
    Write-Info "Checking GitHub token..."
    if (-not $env:GITHUB_TOKEN) {
        Write-Error "GITHUB_TOKEN environment variable is not set!"
        Write-Warning @"
To set the token:
    PowerShell: `$env:GITHUB_TOKEN = 'your_token_here'
    Permanent:  [System.Environment]::SetEnvironmentVariable('GITHUB_TOKEN', 'your_token_here', 'User')

Create token at: https://github.com/settings/tokens
Required scope: write:packages
"@
        exit 1
    }
    Write-Success "GitHub token found"
}

# Build Docker image
if (-not $SkipBuild) {
    Write-Info ""
    Write-Info "=== Building Docker Image ==="
    Write-Info "This may take 5-15 minutes..."
    
    $buildCmd = "docker build -t ${ImageName}:${Version} -t ${ImageName}:latest ."
    Write-Info "Command: $buildCmd"
    
    Invoke-Expression $buildCmd
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Docker build failed!"
        exit 1
    }
    
    Write-Success "Build completed successfully!"
} else {
    Write-Warning "Skipping build step"
}

# Tag images for GitHub Container Registry
Write-Info ""
Write-Info "=== Tagging Images ==="

$tags = @(
    @{Local = "${ImageName}:${Version}"; Remote = "ghcr.io/${GithubUser}/${ImageName}:${Version}"},
    @{Local = "${ImageName}:latest"; Remote = "ghcr.io/${GithubUser}/${ImageName}:latest"}
)

foreach ($tag in $tags) {
    Write-Info "Tagging: $($tag.Local) -> $($tag.Remote)"
    docker tag $tag.Local $tag.Remote
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Tagging failed!"
        exit 1
    }
}

Write-Success "Tagging completed!"

# Login to GitHub Container Registry
if (-not $SkipPush) {
    Write-Info ""
    Write-Info "=== Logging in to GitHub Container Registry ==="
    
    $env:GITHUB_TOKEN | docker login ghcr.io -u $GithubUser --password-stdin
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Login failed!"
        Write-Warning "Check your GITHUB_TOKEN and permissions"
        exit 1
    }
    
    Write-Success "Login successful!"
}

# Push images to registry
if (-not $SkipPush) {
    Write-Info ""
    Write-Info "=== Pushing Images to Registry ==="
    
    foreach ($tag in $tags) {
        Write-Info "Pushing: $($tag.Remote)"
        docker push $tag.Remote
        
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Push failed for $($tag.Remote)!"
            exit 1
        }
        Write-Success "Pushed: $($tag.Remote)"
    }
    
    Write-Success "All images pushed successfully!"
} else {
    Write-Warning "Skipping push step"
}

# Verify images
Write-Info ""
Write-Info "=== Local Images ==="
docker images | Select-String $ImageName

Write-Info ""
Write-Success "=== Process Complete ==="
Write-Info @"

Next steps:
1. Verify on GitHub: https://github.com/$GithubUser?tab=packages
2. Pull and test: docker pull ghcr.io/$GithubUser/${ImageName}:${Version}
3. Run container: docker run --rm ghcr.io/$GithubUser/${ImageName}:${Version}

"@
