NIS2 has been EU law since 2022. In Spain, what is still pending is the national law that transposes it. Waiting for it to appear in the official gazette before looking at your code is a bad idea.

So I built a skill for Claude that reviews a repository through a NIS2 lens.

It looks for secrets hardcoded in the source, disabled TLS verification, obsolete cryptography, injectable SQL, unpinned dependencies, containers running as root and the lack of an incident response plan. It tells you what fails, which article it affects and what to change. And when you ask it for new code, it writes it with those rules in mind from the start.

The most important part is what it does NOT do: it certifies nothing. NIS2 is also policies, training, suppliers, continuity and management accountability, and a scanner cannot see any of that. Every report ends with the list of things you still have to check by hand.

It is open source, dependency-free, tested, and comes with a ready-to-use GitHub Actions workflow.

Repo: [link]

If you work at an essential or important entity and want to try it, I am especially interested in false positives.

#NIS2 #Cybersecurity #OpenSource #Claude
