# Release governance

Every release must carry the source revision in
`org.opencontainers.image.revision` and pass the release provenance workflow.
The custom build script checks that account credential protection and the
offline migration tool are present before it builds an image. Release builds
require a clean committed source checkout so the full Git revision identifies
the code that was actually built. Existing dirty development checkouts are
preserved and work continues in an isolated release branch.

The workflow is a repository check. The GitHub `main` branch still needs an
administrator to require this check, require pull requests, and disallow force
pushes. That server-side rule cannot be inferred from files in this checkout.

The promotion helper also refuses a cloud instance whose current image has no
valid revision label. The existing cloud image is in that bootstrap state; an
administrator must perform the first traceability bootstrap through the normal
reviewed release procedure before subsequent promotions can pass automatically.
