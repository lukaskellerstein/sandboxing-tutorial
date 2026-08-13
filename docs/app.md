I need to design an application, that will help me and my students to learn the sandboxing-tutorial.
Ignore the existing TUI in the project.
The app should have great UI and UX, to explain a lot visually and graphically. Use graphs, animations, infographics, mermaid diagrams to explain concepts, rather than long texts. It is allowed to use texts to explain stuff, but prefer simple images/graphs/infographics/diagrams before long texts.

The app should help us to:
- Explain the environments/boxes for each lesson and solutions (no, gvisor, kata, firecracker, openshell)
- provision a boxes on scaleway for lessons- give ssh access to the boxes
- demonstrate a proof on the boxes that the "solutions" (no, gvisor, kata, firecracker, openshell) are available/installed

- Explain all attacks, their types, what is their goal to demonstrate/perform
- run the attacks on the box on selected "solutions"
- show reports of attack = what was successful and what failed

So the app serves primarily the education reason, it teaches the boxes and solution as well as the attacks/tests (to demonstrate box solution vulnerabilites).  
The user should be easily able to provision the infra for each lesson, and run the attacks that will demonstrate vulnerability of the box with solution.  
Everything should be explain very simply so everyone can quickly understand what the app demonstrates (for beginers), with an option to "get more info" that will show additional page/view with more informations (for advance users).
