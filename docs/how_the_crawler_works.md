# How the VulnScan Pro Crawler Works (In Plain English)

Think of the **Crawler** (also known as a web spider) like an automated cartographer or explorer. Its sole job is to map out a website, find every possible door or window, and collect interesting information along the way, all without human intervention.

Here is the step-by-step breakdown of exactly what it does when you hit "Start Scan".

---

## 1. The Starting Line (The Seed URL)
You give the crawler a starting point, for example: `http://example.com`. 
Before doing anything else, it checks two things:
*   **Robots.txt**: It knocks on the front door and asks the website, *"Are there any rooms you don't want me to enter?"* (It usually looks for paths like `/admin-panel`). Our crawler notes these restricted areas down because, as security testers, hidden areas are highly interesting!
*   **Sensitive Probes**: It blindly knocks on a few common secret doors just to see if they're open, like `/.env` or `/backup.zip`. 

## 2. The "To-Do" List (The Queue)
The crawler uses a highly efficient checkout line called a **Queue**. 
It puts the Starting URL at the front of the line. 
It then proceeds in a loop:
1. Take the first URL out of the line.
2. Visit that URL.
3. Once inside, find *every single link* on that page.
4. If a found link is new (meaning we haven't visited it yet, and it's not already in line), add it to the back of the line.

It repeats this process until the line is empty, or until it hits a pre-defined limit (like "Only visit 100 pages maximum").

## 3. Remembering Where We've Been
To stop itself from walking in circles forever (like going from `Page A` to `Page B` and back to `Page A`), the crawler keeps a massive notepad of everywhere it has already been. This is called the **Visited Set**. If a link is already in the notepad, the crawler ignores it.

## 4. Being Polite (Rate Limiting)
Real web servers get angry if you knock on their doors 10,000 times a second. Our crawler has a built-in `delay` feature. It physically pauses for a fraction of a second before asking for the next page so it doesn't accidentally crash the target website.

## 5. Harvesting the Gold (Data Extraction)
While the crawler is reading a page to find more links, it's also scanning the text for valuable information. It uses pattern matching and HTML parsers (like reading the Matrix code) to rip out:
*   **Forms & Inputs:** It finds every search bar, login screen, and upload button and notes exactly how they work. (This is handed off to the XSS and SQLi scanners later).
*   **Emails:** It grabs any contact email addresses it sees.
*   **Hidden Secrets:** It reads the invisible HTML "comments" left behind by developers and looks for words like `password` or `api_key`.
*   **Security Headers:** It checks if the website's firewall and encryption headers are configured safely.
*   **Tech Stack:** It peeks at the `<meta>` tags to figure out if the site was built with WordPress, React, or pure Python.

## 6. The Final Report
Once the crawler finishes its map (or hits its maximum page limit), it turns around and hands a massive, organized dictionary back to VulnScan Pro. This dictionary contains all the forms to attack, all the scripts to analyze, and all the security misconfigurations it noticed during its journey.
