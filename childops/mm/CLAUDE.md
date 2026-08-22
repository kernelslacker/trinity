# childops/mm/ — Memory-Management Childops

## Files (1)
- `pagecache-canary-check` — writes a known pattern through the pagecache and
  re-verifies it, so a corruption shows up as a content mismatch rather than
  as an unexplained oops later.
