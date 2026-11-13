# Email privacy of commits

**Status (Mission 14, 2026-11-13).** Every commit records an author and committer email, and in a public repository anyone can read them (`git log`, the GitHub API, patch downloads). This page records what the maintainer's commits expose, what cannot be changed, and the steps that keep the address private from now on. It names no address.

## Findings

| Check | Result |
|---|---|
| Commits in RChefo/ExploitX (the 222 commits of the release branch up to Mission 13) | All authored with the maintainer's **personal email address**, which is therefore already public in the history. Mission 14's commits use the same configured address, since no verified replacement exists yet |
| Commits in RChefo/ExploitX-Web | The maintainer's 11 commits use the same personal address, including the "Initial commit" made on github.com |
| GitHub's "Keep my email addresses private" | **Off**: a commit made on github.com would use the private `noreply` address if it were on, and the web-made "Initial commit" uses the personal address |
| The maintainer's `noreply` address | **Not verified.** The CLI token has no `user` scope, so the account's addresses cannot be listed, and no commit made by GitHub on the maintainer's behalf carries it. It is not guessed here |
| Local Git configuration (`user.email`) | The personal address; **left unchanged**, because the replacement could not be verified |
| Dependabot's commits | Use Dependabot's own `noreply` address |

## What cannot be changed

Removing the address from existing commits would mean rewriting the public history: new commit IDs for every commit, broken links to commits, release tags and pull requests, and every clone diverging. That is not done (and is not allowed without the owner's explicit decision). The addresses in published commits stay visible; the steps below stop new ones.

## Steps for the maintainer (in this order)

1. **Find the `noreply` address** at <https://github.com/settings/emails>, under "Keep my email addresses private". For accounts created since July 2017 it has the form `<numeric id>+<login>@users.noreply.github.com`; copy it from that page rather than building it by hand.
2. **Use it for commits** in both repositories, or for all repositories:
   ```
   git config --global user.email "<the noreply address from step 1>"
   ```
   (`git config user.email …` inside one clone changes only that clone.)
3. **Turn on "Keep my email addresses private"** on the same page. Commits made on github.com (web edits, merges, squash merges) then use the `noreply` address.
4. **Then turn on "Block command line pushes that expose my email".** GitHub then rejects a push whose commits carry the personal address. Do this only after step 2, or the next push is refused.
5. Optionally, remove the personal address from the public profile (Settings > Public profile > Public email) if it should not be shown there either.

## For contributors

* Use your own `noreply` address for `user.email` if you do not want your address published; it works for sign-offs too ([CONTRIBUTOR_TERMS.md](CONTRIBUTOR_TERMS.md)).
* Never put personal addresses in issues, logs or documentation; the project's documents refer to people by role.
