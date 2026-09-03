"""FastAPI application entry point for the Deploy Approval Agent (stateless).

Runtime persistence is solely the GitHub lifecycle comment hidden state.
Single writer: only GitHubCommandWatcher mutates deploy state.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from .config import Config, DEFAULT_GITHUB_REPOS, load_config
from .github_client import GitHubClient
from .github_state_proxy import GitHubStateProxy
from .github_command_watcher import GitHubCommandWatcher
from .policy import Policy
from .registry_client import RegistryClient
from .review_client import ReviewAgentClient
from .router_webhook import router as webhook_router
from .service import DeployController

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


_STATUS_LABEL_SPECS = (
    (
        "status: review-required",
        "D93F0B",
        "Deploy Approval: current HEAD requires review",
    ),
    (
        "status: reviewing",
        "5319E7",
        "Deploy Approval: current HEAD is being reviewed",
    ),
    (
        "status: deploy-ready",
        "0E8A16",
        "Deploy Approval: reviewed HEAD is ready for deploy request",
    ),
    (
        "status: deploy-requested",
        "FBCA04",
        "Deploy Approval: Machine Owner action required",
    ),
    (
        "status: testing",
        "1D76DB",
        "Deploy Approval: deployment complete; human testing required",
    ),
    (
        "status: succeeded",
        "0E8A16",
        "Deploy Approval: human validation passed",
    ),
    (
        "status: failed",
        "B60205",
        "Deploy Approval: deployment or validation failed",
    ),
)


def _validate_current_user_identity(user: dict) -> tuple[str, str]:
    user_id = user.get("id")
    login = user.get("login")
    if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id <= 0:
        raise ValueError("authenticated GitHub user id must be a positive int")
    if not isinstance(login, str) or not login.strip():
        raise ValueError("authenticated GitHub login must be non-empty")
    return str(user_id), login.strip()


def _validate_label_namespace(repo: str, labels: list[dict]) -> dict[str, dict]:
    if not isinstance(labels, list):
        raise ValueError(f"repository {repo}: labels response must be a list")
    exact: dict[str, dict] = {}
    casefold_seen: dict[str, str] = {}
    for label in labels:
        if not isinstance(label, dict):
            raise ValueError(f"repository {repo}: label record must be an object")
        name = label.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"repository {repo}: label name must be a non-empty string")
        name = name.strip()
        lowered = name.casefold()
        if name in exact:
            raise ValueError(
                f"repository {repo}: duplicate label record {name!r}"
            )
        existing = casefold_seen.get(lowered)
        if existing is not None and existing != name:
            raise ValueError(
                f"repository {repo}: existing conflicting label {existing!r} "
                f"conflicts with required exact label {name!r}"
            )
        exact[name] = label
        casefold_seen[lowered] = name
    return exact


async def _bootstrap_status_labels(github: GitHubClient) -> None:
    """Ensure the canonical status labels exist on both supported repos."""
    namespaces: dict[str, dict[str, dict]] = {}

    # Phase A: read/validate both repos before any mutation.
    for repo in DEFAULT_GITHUB_REPOS:
        labels = await github.list_repository_labels(repo)
        namespaces[repo] = _validate_label_namespace(repo, labels)
        lower_names = {name.casefold(): name for name in namespaces[repo]}
        for spec_name, _, _ in _STATUS_LABEL_SPECS:
            conflicting = lower_names.get(spec_name.casefold())
            if conflicting is not None and conflicting != spec_name:
                raise ValueError(
                    f"repository {repo}: existing conflicting label {conflicting!r} "
                    f"conflicts with required exact label {spec_name!r}"
                )

    # Phase B: create missing exact labels only, serially, in repo order.
    for repo in DEFAULT_GITHUB_REPOS:
        exact = namespaces[repo]
        for name, color, description in _STATUS_LABEL_SPECS:
            if name in exact:
                logger.info("label bootstrap keep %s %s", repo, name)
                continue
            try:
                await github.create_repository_label(repo, name, color, description)
            except Exception as exc:
                fresh_exact = _validate_label_namespace(
                    repo, await github.list_repository_labels(repo)
                )
                if name in fresh_exact:
                    logger.info("label bootstrap race-satisfied %s %s", repo, name)
                    exact = fresh_exact
                    continue
                raise exc
            exact[name] = {"name": name, "color": color, "description": description}

    # Final verification: fresh GET on both repos, exact labels present.
    for repo in DEFAULT_GITHUB_REPOS:
        final_exact = _validate_label_namespace(
            repo, await github.list_repository_labels(repo)
        )
        missing = [name for name, _, _ in _STATUS_LABEL_SPECS if name not in final_exact]
        if missing:
            raise ValueError(
                f"repository {repo}: missing required labels after bootstrap: "
                + ", ".join(missing)
            )


def create_app(config: Config | None = None):
    """Build the FastAPI app.

    Single writer: only GitHubCommandWatcher is started.
    No Poller, no second mutation loop.
    """
    config = config or load_config()
    policy = Policy(config)
    policy.load_machines()
    github = GitHubClient(config)
    review = ReviewAgentClient(config)
    registry = RegistryClient(config)

    proxy = GitHubStateProxy(config, github)

    controller = DeployController(
        config, proxy, policy, github, review, registry,
        agent_core_factory=None,
    )

    # Single serial command watcher
    watcher = GitHubCommandWatcher(config, proxy, controller)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        current_user = await github.get_current_user()
        bot_user_id, bot_login = _validate_current_user_identity(current_user)
        proxy.bind_trusted_identity(bot_user_id, bot_login)
        await _bootstrap_status_labels(github)
        watcher.start()
        try:
            yield
        finally:
            await watcher.stop()
            close = getattr(controller, "aclose", None)
            if close is not None:
                await close()
            for client in (github, review, registry):
                http = getattr(client, "http", None)
                aclose = getattr(http, "aclose", None)
                if aclose is not None:
                    await aclose()

    app = FastAPI(title="Deploy Approval Agent", lifespan=lifespan)
    app.state.config = config
    app.state.policy = policy
    app.state.github = github
    app.state.review = review
    app.state.registry = registry
    app.state.controller = controller
    app.state.proxy = proxy
    app.state.watcher = watcher

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    app.include_router(webhook_router)
    return app


def main():
    config = load_config()
    if not config.api_token:
        logger.error(
            "Refusing to start: API_TOKEN is required. Set API_TOKEN to a "
            "random secret and pass it to the container."
        )
        raise SystemExit(1)
    app = create_app(config)
    uvicorn.run(app, host=config.host, port=config.port, log_level="info")


if __name__ == "__main__":
    main()
