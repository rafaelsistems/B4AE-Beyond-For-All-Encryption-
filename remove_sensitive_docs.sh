#!/bin/bash

# WARNING: This script removes sensitive documentation from git repository
# Files will be kept locally but removed from git tracking
# Run this script from the repository root directory

echo "=================================================="
echo "Removing Sensitive Documentation from Git"
echo "=================================================="
echo ""
echo "This will remove the following from git (but keep locally):"
echo "  - .kiro/ (internal specs and configurations)"
echo "  - docs/business/ (business strategy, partnerships)"
echo "  - docs/compliance/ (certifications, audits, government bids)"
echo "  - docs/archive/ (internal planning, old checklists)"
echo "  - docs/*_SUMMARY.md and AUDIT_REPORT.md (internal process docs)"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo "Removing sensitive folders from git..."

# Remove .kiro folder (internal specs and configurations)
if [ -d ".kiro" ]; then
    git rm -r --cached .kiro/
    echo "✓ Removed .kiro/ from git"
fi

# Remove business folder (8 files - partnerships, funding, strategy)
if [ -d "docs/business" ]; then
    git rm -r --cached docs/business/
    echo "✓ Removed docs/business/ from git"
fi

# Remove compliance folder (10 files - certifications, audits, government)
if [ -d "docs/compliance" ]; then
    git rm -r --cached docs/compliance/
    echo "✓ Removed docs/compliance/ from git"
fi

# Remove archive folder (9 files - old planning, checklists)
if [ -d "docs/archive" ]; then
    git rm -r --cached docs/archive/
    echo "✓ Removed docs/archive/ from git"
fi

# Remove internal audit/summary documents
git rm --cached docs/P1_DOCUMENTATION_UPDATE_SUMMARY.md 2>/dev/null && echo "✓ Removed P1_DOCUMENTATION_UPDATE_SUMMARY.md"
git rm --cached docs/P2_P3_DOCUMENTATION_UPDATE_SUMMARY.md 2>/dev/null && echo "✓ Removed P2_P3_DOCUMENTATION_UPDATE_SUMMARY.md"
git rm --cached docs/DOCUMENTATION_AUDIT_REPORT.md 2>/dev/null && echo "✓ Removed DOCUMENTATION_AUDIT_REPORT.md"

echo ""
echo "=================================================="
echo "Removal Complete"
echo "=================================================="
echo ""
echo "Next steps:"
echo "1. Verify changes: git status"
echo "2. Commit changes: git commit -m 'Remove sensitive documentation from repository'"
echo "3. Push to remote: git push origin main"
echo ""
echo "Note: Files are still on your local disk in docs/ folders"
echo "They are now listed in .gitignore and won't be tracked by git"
echo ""
