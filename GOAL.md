Could you help me to prepare syllabus for this tutorial? It should be based on this /Users/lukaskellerstein/Projects/Github/lukaskellerstein/agent-eval-benchmark/tutorial/03_sandboxing,
  and cover the topic of sandboxing, but without any mlflow or langfuse. Purely just the sandboxing, and only thing it should integrate with, are the agents.

  it should use podman (if podman is not an option for some reason, use docker).
  it should use pure k8s and Openshift
  it should use agents - langchain/langgraph, deepagents, claude agents SDK - ex. /Users/lukaskellerstein/Projects/Github/lukaskellerstein/agent-eval-benchmark/shared/shared/core/agents

  In the project, we should have a folder infra/ where I can run via one command everything i need for the tutorial (except k8s??) - ex.
  /Users/lukaskellerstein/Projects/Github/lukaskellerstein/agent-eval-benchmark/infra

  For sandboxing, it should demonstrate:
- no sandboxing
- local container
- local container with gVisor
- local openshell
- k8s
- k8s with gvisor
- k8s with Kata containers
- k8s with openshell
