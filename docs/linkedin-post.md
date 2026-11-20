NIS2 has been EU law since 2022. In Spain, what is still pending is the national law that transposes it. Waiting for it to appear in the official gazette before looking at your code is a bad idea.

So I built a free, open-source skill for Claude that reviews a repository through the lens of four EU regulations: NIS2, GDPR, the AI Act and DORA.

It looks for secrets hardcoded in the source, disabled TLS verification, obsolete cryptography, injectable SQL, unpinned dependencies, containers running as root, personal data in logs or sent to an LLM, missing AI disclosure, and external calls with no timeout. It tells you what fails, which article it affects and what to change. And when you ask it for new code, it writes it with those rules in mind from the start.

The most important part is what it does NOT do: it certifies nothing. These regulations are also policies, training, suppliers, continuity and management accountability, and a scanner cannot see any of that. Every report ends with the list of things you still have to check by hand.

It is dependency-free Python, has 36 tests, and comes with a GitHub Actions workflow with pinned actions.

Repo: https://github.com/fjaguayo/nis2-guard

If you work at an essential or important entity and want to try it, I am especially interested in false positives.

#NIS2 #GDPR #AIAct #DORA #Cybersecurity #OpenSource #Claude
