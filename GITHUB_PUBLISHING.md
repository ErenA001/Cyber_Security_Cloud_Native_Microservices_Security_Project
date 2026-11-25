# Publishing this update to GitHub

## Apply and push the project update

1. Download and extract `CloudGuard-GitHub-Update.zip`.
2. Open Terminal and `cd` into the root of the cloned `Cyber_Security_Cloud_Native_Microservices_Security_Project` repository.
3. Run the update helper from the extracted bundle:

   ```bash
   bash ~/Downloads/CloudGuard-GitHub-Update/scripts/apply_github_update.sh
   ```

4. The helper refuses to run if the Git working tree is already dirty. It copies the 2.0.1 source and evidence files, preserves the local `.env`, stages the update, shows the staged diff, and asks before committing and pushing the current branch.

## Make the MP4 play inline in the GitHub README

The bundle includes an MP4 and an animated GIF preview. The GIF plays inline as a normal README image. For an inline GitHub video player, the MP4 must be uploaded as a GitHub-hosted Markdown attachment; a plain link to an MP4 committed in the repository is not equivalent.

If GitHub CLI 2.99.0 or newer is installed and authenticated, run this from the cloned repository root:

```bash
bash ~/Downloads/CloudGuard-GitHub-Update/scripts/attach_demo_video_to_github.sh
```

The helper creates a temporary issue, attaches the MP4 using GitHub CLI's `--attach` support, inserts the generated asset URL into the README, pushes that README change, and closes the temporary issue. It asks for confirmation first. GitHub documents `--attach` for uploading local media to issues, pull requests, and comments; the generated attachment URL is then used in the README.

Alternatively, edit `README.md` on GitHub and drag `docs/demo/cloudguard-ai-overview-demo.mp4` into the Markdown editor. GitHub will insert a hosted media attachment; leave its URL on a line by itself for inline playback.

## Scope of the demo media

`cloudguard-ai-overview-demo.mp4` is a short, silent walkthrough assembled from the three supplied application screenshots. It covers the Overview dashboard, AI analysis in progress, and the completed NVIDIA NIM analyst briefing. It is not a live screen recording and does not demonstrate every page. For a complete group presentation, record the Security Lab, Event Log, Settings, image scan/report, and JSON export workflows from the running application.
