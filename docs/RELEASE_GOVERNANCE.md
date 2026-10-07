# Release governance

Every custom release carries the exact source revision and owned fork in its image labels. Builds require a clean committed checkout, credential-protection sources, and the offline migration tool. Promotion verifies the immutable revision in the owned fork, successful required CI checks, and strict branch protection applying to administrators.

Install and accept the image locally with Update-Local before promotion. When source is in a managed worktree and the existing local runtime is elsewhere, set SUB2API_RUNTIME_ROOT to that runtime's project directory for the installation, acceptance, and promotion commands. The scripts execute the reviewed source while retaining the runtime's own data, configuration, and independent encryption roots.

Local acceptance starts the previous protected image against the migrated isolated database and verifies record integrity, key bindings, and protected-data counts. A different cloud image must be included in this rollback compatibility receipt before promotion.

Cloud promotion verifies its starting image, completes the encrypted backup, and changes the live override's image. It checks container health, source revision, version, environment, hardening, mounts, and networks. If promotion fails and the migration receipt remains identical, it restores the exact previous override and compatible runtime. If migrations changed or compatibility cannot be verified, rollback stops and the paired encrypted backups remain available for the dedicated recovery procedure.

Fault injection regression covers startup failure, health timeout, configuration drift, wrong version, migration changes, backup failure, and a changed cloud baseline. The release-helpers CI runs deploy/tests/test_cloud_release_transaction.py.
