#!/bin/bash
# B4AE Docker Build and Publish Script
# Version: 2.0.0
# Description: Automates Docker image build and publish to GitHub Container Registry

set -e

# Default values
VERSION="2.0.0"
GITHUB_USER="rafaelsistems"
IMAGE_NAME="b4ae"
SKIP_BUILD=false
SKIP_PUSH=false

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

function print_success { echo -e "${GREEN}$1${NC}"; }
function print_info { echo -e "${CYAN}$1${NC}"; }
function print_warning { echo -e "${YELLOW}$1${NC}"; }
function print_error { echo -e "${RED}$1${NC}"; }

# Help message
function show_help {
    cat << EOF
B4AE Docker Build and Publish Script

USAGE:
    ./docker-publish.sh [OPTIONS]

OPTIONS:
    -v, --version <version>    Version tag (default: 2.0.0)
    -u, --user <user>          GitHub username (default: rafaelsistems)
    -i, --image <name>         Image name (default: b4ae)
    --skip-build               Skip the build step
    --skip-push                Skip the push step
    -h, --help                 Show this help message

EXAMPLES:
    ./docker-publish.sh
    ./docker-publish.sh -v 2.1.0
    ./docker-publish.sh --skip-build
    ./docker-publish.sh --skip-push

PREREQUISITES:
    1. Docker must be running
    2. GITHUB_TOKEN environment variable must be set
    3. Token must have 'write:packages' scope

EOF
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -u|--user)
            GITHUB_USER="$2"
            shift 2
            ;;
        -i|--image)
            IMAGE_NAME="$2"
            shift 2
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --skip-push)
            SKIP_PUSH=true
            shift
            ;;
        -h|--help)
            show_help
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            ;;
    esac
done

print_info "=== B4AE Docker Build and Publish ==="
print_info "Version: $VERSION"
print_info "Registry: ghcr.io/$GITHUB_USER/$IMAGE_NAME"
echo ""

# Check if Docker is running
print_info "Checking Docker status..."
if ! docker version > /dev/null 2>&1; then
    print_error "Docker is not running!"
    print_warning "Please start Docker and try again."
    exit 1
fi
DOCKER_VERSION=$(docker version --format '{{.Server.Version}}')
print_success "Docker is running (version: $DOCKER_VERSION)"

# Check for GITHUB_TOKEN
if [ "$SKIP_PUSH" = false ]; then
    print_info "Checking GitHub token..."
    if [ -z "$GITHUB_TOKEN" ]; then
        print_error "GITHUB_TOKEN environment variable is not set!"
        print_warning "To set the token:"
        echo "    export GITHUB_TOKEN='your_token_here'"
        echo ""
        echo "Create token at: https://github.com/settings/tokens"
        echo "Required scope: write:packages"
        exit 1
    fi
    print_success "GitHub token found"
fi

# Build Docker image
if [ "$SKIP_BUILD" = false ]; then
    echo ""
    print_info "=== Building Docker Image ==="
    print_info "This may take 5-15 minutes..."
    
    BUILD_CMD="docker build -t ${IMAGE_NAME}:${VERSION} -t ${IMAGE_NAME}:latest ."
    print_info "Command: $BUILD_CMD"
    
    eval $BUILD_CMD
    
    print_success "Build completed successfully!"
else
    print_warning "Skipping build step"
fi

# Tag images for GitHub Container Registry
echo ""
print_info "=== Tagging Images ==="

declare -a TAGS=(
    "${IMAGE_NAME}:${VERSION}|ghcr.io/${GITHUB_USER}/${IMAGE_NAME}:${VERSION}"
    "${IMAGE_NAME}:latest|ghcr.io/${GITHUB_USER}/${IMAGE_NAME}:latest"
)

for tag_pair in "${TAGS[@]}"; do
    IFS='|' read -r local_tag remote_tag <<< "$tag_pair"
    print_info "Tagging: $local_tag -> $remote_tag"
    docker tag "$local_tag" "$remote_tag"
done

print_success "Tagging completed!"

# Login to GitHub Container Registry
if [ "$SKIP_PUSH" = false ]; then
    echo ""
    print_info "=== Logging in to GitHub Container Registry ==="
    
    echo "$GITHUB_TOKEN" | docker login ghcr.io -u "$GITHUB_USER" --password-stdin
    
    print_success "Login successful!"
fi

# Push images to registry
if [ "$SKIP_PUSH" = false ]; then
    echo ""
    print_info "=== Pushing Images to Registry ==="
    
    docker push "ghcr.io/${GITHUB_USER}/${IMAGE_NAME}:${VERSION}"
    print_success "Pushed: ghcr.io/${GITHUB_USER}/${IMAGE_NAME}:${VERSION}"
    
    docker push "ghcr.io/${GITHUB_USER}/${IMAGE_NAME}:latest"
    print_success "Pushed: ghcr.io/${GITHUB_USER}/${IMAGE_NAME}:latest"
    
    print_success "All images pushed successfully!"
else
    print_warning "Skipping push step"
fi

# Verify images
echo ""
print_info "=== Local Images ==="
docker images | grep "$IMAGE_NAME" || true

echo ""
print_success "=== Process Complete ==="
cat << EOF

Next steps:
1. Verify on GitHub: https://github.com/$GITHUB_USER?tab=packages
2. Pull and test: docker pull ghcr.io/$GITHUB_USER/${IMAGE_NAME}:${VERSION}
3. Run container: docker run --rm ghcr.io/$GITHUB_USER/${IMAGE_NAME}:${VERSION}

EOF
