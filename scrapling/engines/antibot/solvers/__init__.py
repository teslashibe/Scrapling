"""Operator-paid CAPTCHA solver clients (CapMonster Cloud, CapSolver, 2Captcha), a router and token injectors.

Nothing here runs unless the caller supplies provider keys, e.g.::

    router = SolverRouter.from_config({"capmonster": "KEY", "capsolver": "KEY", "2captcha": "KEY"})
    token = await router.scope().solve_token("turnstile", sitekey, page_url, deadline=deadline)
"""

from .base import (
    ALL_KINDS,
    EXPERIMENTAL_KINDS,
    RECOGNITION_KINDS,
    TOKEN_KINDS,
    SolveRecord,
    Solver,
    SolverAuthError,
    SolverBadRequest,
    SolverBalanceError,
    SolverBudgetExceeded,
    SolverConfigError,
    SolverError,
    SolverProxyNotAllowed,
    SolverRateLimited,
    SolverTimeout,
    SolverUnavailable,
    SolverUnsolvable,
    SolverUnsupported,
    Token,
)
from ._client import CreateTaskSolver, UrllibTransport, recaptcha_label_id, recaptcha_label_text
from .capmonster import CapMonsterSolver
from .capsolver import CapSolverSolver
from .twocaptcha import TwoCaptchaSolver
from .router import DEFAULT_ROUTES, SolverRouter
from .inject import (
    capture_script,
    evaluate_main_world,
    find_widgets,
    inject_hcaptcha,
    inject_recaptcha,
    inject_token,
    inject_turnstile,
    install_capture,
    read_captured,
    set_aws_waf_cookie,
    token_request,
)

__all__ = [
    "ALL_KINDS",
    "EXPERIMENTAL_KINDS",
    "RECOGNITION_KINDS",
    "TOKEN_KINDS",
    "DEFAULT_ROUTES",
    "Token",
    "SolveRecord",
    "Solver",
    "SolverError",
    "SolverAuthError",
    "SolverBadRequest",
    "SolverBalanceError",
    "SolverBudgetExceeded",
    "SolverConfigError",
    "SolverProxyNotAllowed",
    "SolverRateLimited",
    "SolverTimeout",
    "SolverUnavailable",
    "SolverUnsolvable",
    "SolverUnsupported",
    "CreateTaskSolver",
    "UrllibTransport",
    "CapMonsterSolver",
    "CapSolverSolver",
    "TwoCaptchaSolver",
    "SolverRouter",
    "recaptcha_label_id",
    "recaptcha_label_text",
    "capture_script",
    "install_capture",
    "evaluate_main_world",
    "read_captured",
    "find_widgets",
    "token_request",
    "inject_turnstile",
    "inject_recaptcha",
    "inject_hcaptcha",
    "inject_token",
    "set_aws_waf_cookie",
]
